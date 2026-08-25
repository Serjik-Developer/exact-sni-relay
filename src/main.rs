#![cfg(target_os = "linux")]

mod config;
mod metrics;
mod splice;
mod tls;

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use arc_swap::ArcSwap;
use clap::Parser;
use config::{Admission, Config};
use metrics::{Metrics, UpstreamClass};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpSocket, TcpStream},
    signal::unix::{signal, SignalKind},
    sync::{broadcast, mpsc, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};

const INITIAL_BUFFER_CAPACITY: usize = 4 * 1024;
#[cfg(test)]
const TEST_EXCHANGE_BYTES: usize = 32;
const MAX_DRAIN_TIME: Duration = Duration::from_secs(10);
// A proxied connection owns two TCP sockets. Keep ample headroom below a
// typical high LimitNOFILE and the configured scoped admission budget.
const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 75_000;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check_config: bool,
    #[arg(
        long,
        default_value_t = DEFAULT_MAX_CONCURRENT_CONNECTIONS,
        value_parser = parse_max_connections
    )]
    max_connections: usize,
}

fn parse_max_connections(value: &str) -> Result<usize, String> {
    let value = value
        .parse::<usize>()
        .map_err(|_| "max-connections must be an integer".to_string())?;
    if !(1..=DEFAULT_MAX_CONCURRENT_CONNECTIONS).contains(&value) {
        return Err(format!(
            "max-connections must be between 1 and {DEFAULT_MAX_CONCURRENT_CONNECTIONS}"
        ));
    }
    Ok(value)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let initial = Config::from_path(&args.config)?;
    if args.check_config {
        println!("configuration is valid");
        return Ok(());
    }
    run_with_limit(args.config, initial, None, args.max_connections).await?;
    Ok(())
}

async fn run_with_limit(
    config_path: PathBuf,
    initial: Config,
    ready: Option<mpsc::Sender<(SocketAddr, SocketAddr)>>,
    max_concurrent_connections: usize,
) -> io::Result<()> {
    let admission = Arc::new(AdmissionControl::new(
        initial.admission,
        max_concurrent_connections,
    )?);
    let listener = TcpListener::bind(initial.bind).await?;
    set_listener_backlog(&listener, max_concurrent_connections)?;
    let health_listener = TcpListener::bind(initial.health_bind).await?;
    let listen_address = listener.local_addr()?;
    let health_address = health_listener.local_addr()?;
    let config = Arc::new(ArcSwap::from_pointee(initial));
    let metrics = Metrics::new().map_err(io::Error::other)?;
    let mut health_task = tokio::spawn(metrics::serve(health_listener, metrics.clone()));
    if let Some(ready) = ready {
        let _ = ready.send((listen_address, health_address)).await;
    }

    let mut connections = JoinSet::new();
    let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, peer_address) = accept?;
                let permit = match Arc::clone(&admission.pre_parse).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        metrics.rejected_pre_parse.inc();
                        drop(stream);
                        continue;
                    }
                };
                let connection_config = config.load_full();
                let connection_metrics = metrics.clone();
                let connection_admission = Arc::clone(&admission);
                connections.spawn(async move {
                    connection_metrics.accepted.inc();
                    connection_metrics.active.inc();
                    connection_metrics.active_pre_parse.inc();
                    // Expected parse, timeout, disconnect, and backend errors are
                    // counted, not logged per connection. This avoids attacker-
                    // controlled journald amplification on the public data path.
                    let _ = handle_connection_admitted(
                        stream,
                        canonical_source_ip(peer_address.ip()),
                        connection_config,
                        &connection_metrics,
                        &connection_admission,
                        permit,
                    )
                    .await;
                    connection_metrics.active.dec();
                });
            }
            _ = sighup.recv() => {
                match Config::from_path(&config_path) {
                    Ok(reloaded) if reloaded.bind == listen_address && reloaded.health_bind == health_address => {
                        if reloaded.admission != admission.configured {
                            metrics.reload_errors.inc();
                            eprintln!("reload rejected: admission limits cannot change without a restart");
                        } else {
                            config.store(Arc::new(reloaded));
                            metrics.reload_success.inc();
                        }
                    }
                    Ok(_) => {
                        metrics.reload_errors.inc();
                        eprintln!("reload rejected: bind and health_bind cannot change without a restart");
                    }
                    Err(error) => {
                        metrics.reload_errors.inc();
                        eprintln!("reload rejected: {error}");
                    }
                }
            }
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            _ = shutdown_rx.recv() => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    eprintln!("connection task failed: {error}");
                }
            }
        }
    }

    drop(listener);
    let _ = shutdown_tx.send(());
    health_task.abort();
    let _ = (&mut health_task).await;
    let drain = async {
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                eprintln!("connection task failed during shutdown: {error}");
            }
        }
    };
    if timeout(MAX_DRAIN_TIME, drain).await.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}

fn set_listener_backlog(
    listener: &TcpListener,
    max_concurrent_connections: usize,
) -> io::Result<()> {
    let backlog = max_concurrent_connections.min(libc::c_int::MAX as usize) as libc::c_int;
    if unsafe { libc::listen(listener.as_raw_fd(), backlog) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

struct AdmissionControl {
    configured: Admission,
    pre_parse: Arc<Semaphore>,
    routed: Arc<Semaphore>,
    routed_sources: Arc<SourceAdmission>,
    fallback: Arc<Semaphore>,
}

impl AdmissionControl {
    fn new(scoped: Admission, process_max_connections: usize) -> io::Result<Self> {
        let configured = scoped
            .pre_parse_max_connections
            .checked_add(scoped.routed_max_connections)
            .and_then(|value| value.checked_add(scoped.fallback_max_connections))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "admission budget overflow")
            })?;
        if configured > process_max_connections {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "scoped admission budget {configured} exceeds --max-connections {process_max_connections}"
                ),
            ));
        }
        Ok(Self {
            configured: scoped,
            pre_parse: Arc::new(Semaphore::new(scoped.pre_parse_max_connections)),
            routed: Arc::new(Semaphore::new(scoped.routed_max_connections)),
            routed_sources: Arc::new(SourceAdmission::new(
                scoped.routed_max_connections_per_source,
            )),
            fallback: Arc::new(Semaphore::new(scoped.fallback_max_connections)),
        })
    }
}

struct SourceAdmission {
    max_connections: usize,
    active: Mutex<HashMap<IpAddr, usize>>,
}

impl SourceAdmission {
    fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            active: Mutex::new(HashMap::new()),
        }
    }

    fn try_acquire(self: &Arc<Self>, source: IpAddr) -> Option<SourcePermit> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let count = active.entry(source).or_default();
        if *count >= self.max_connections {
            return None;
        }
        *count += 1;
        Some(SourcePermit {
            admission: Arc::clone(self),
            source,
        })
    }

    fn release(&self, source: IpAddr) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(count) = active.get_mut(&source) {
            *count -= 1;
            if *count == 0 {
                active.remove(&source);
            }
        }
    }
}

struct SourcePermit {
    admission: Arc<SourceAdmission>,
    source: IpAddr,
}

impl Drop for SourcePermit {
    fn drop(&mut self) {
        self.admission.release(self.source);
    }
}

fn canonical_source_ip(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V6(source) => source
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(source)),
        source => source,
    }
}

enum ClassifiedTarget {
    Routed {
        target: SocketAddr,
        socket_marks: Option<config::SocketMarks>,
        route_label: String,
    },
    Fallback {
        target: SocketAddr,
        route_label: &'static str,
    },
}

#[derive(Clone, Copy)]
struct ConnectDiagnostics<'a> {
    class: UpstreamClass,
    route_label: &'a str,
}

#[derive(Clone, Copy)]
struct ProxyUpstream<'a> {
    address: SocketAddr,
    socket_marks: Option<config::SocketMarks>,
    diagnostics: ConnectDiagnostics<'a>,
}

async fn handle_connection_admitted(
    mut client: TcpStream,
    source: IpAddr,
    config: Arc<Config>,
    metrics: &Metrics,
    admission: &AdmissionControl,
    pre_parse_permit: OwnedSemaphorePermit,
) -> io::Result<()> {
    let mut pre_parse_gauge = GaugeGuard::already_incremented(metrics.active_pre_parse.clone());
    client.set_nodelay(true)?;
    let (classification, buffered) = classify_client(&client, &config, metrics).await?;
    let target = classify_target(classification, &config, metrics);
    match target {
        ClassifiedTarget::Routed {
            target,
            socket_marks,
            route_label,
        } => {
            let _source_permit = match admission.routed_sources.try_acquire(source) {
                Some(permit) => permit,
                None => {
                    metrics.rejected_routed.inc();
                    metrics.rejected_routed_source.inc();
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "per-source routed admission limit reached",
                    ));
                }
            };
            let permit = match Arc::clone(&admission.routed).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    metrics.rejected_routed.inc();
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "routed admission limit reached",
                    ));
                }
            };
            drop(pre_parse_permit);
            pre_parse_gauge.release();
            let _routed_gauge = GaugeGuard::new(metrics.active_routed.clone());
            let _established_gauge = GaugeGuard::new(metrics.active_routed_established.clone());
            let result = proxy_classified(
                &mut client,
                ProxyUpstream {
                    address: target,
                    socket_marks,
                    diagnostics: ConnectDiagnostics {
                        class: UpstreamClass::Routed,
                        route_label: &route_label,
                    },
                },
                buffered,
                &config,
                metrics,
                None,
            )
            .await;
            drop(permit);
            result
        }
        ClassifiedTarget::Fallback {
            target,
            route_label,
        } => {
            let permit = match Arc::clone(&admission.fallback).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    metrics.rejected_fallback.inc();
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "fallback admission limit reached",
                    ));
                }
            };
            drop(pre_parse_permit);
            pre_parse_gauge.release();
            let _active_gauge = GaugeGuard::new(metrics.active_fallback.clone());
            let result = proxy_classified(
                &mut client,
                ProxyUpstream {
                    address: target,
                    socket_marks: None,
                    diagnostics: ConnectDiagnostics {
                        class: UpstreamClass::Fallback,
                        route_label,
                    },
                },
                buffered,
                &config,
                metrics,
                Some(config.fallback_lifetime_timeout()),
            )
            .await;
            drop(permit);
            result
        }
    }
}

struct GaugeGuard {
    gauge: prometheus::IntGauge,
    armed: bool,
}

impl GaugeGuard {
    fn new(gauge: prometheus::IntGauge) -> Self {
        gauge.inc();
        Self { gauge, armed: true }
    }

    fn already_incremented(gauge: prometheus::IntGauge) -> Self {
        Self { gauge, armed: true }
    }

    fn release(&mut self) {
        if self.armed {
            self.gauge.dec();
            self.armed = false;
        }
    }
}

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
async fn handle_connection(
    client: TcpStream,
    config: Arc<Config>,
    metrics: &Metrics,
) -> io::Result<()> {
    let admission = AdmissionControl::new(
        config.admission,
        config.admitted_connection_budget().unwrap(),
    )?;
    let permit = Arc::clone(&admission.pre_parse)
        .try_acquire_owned()
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "test pre-parse admission full"))?;
    metrics.active_pre_parse.inc();
    handle_connection_admitted(
        client,
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        config,
        metrics,
        &admission,
        permit,
    )
    .await
}

async fn classify_client(
    client: &TcpStream,
    config: &Config,
    metrics: &Metrics,
) -> io::Result<(tls::Classification, Vec<u8>)> {
    let (classification, buffered) = match timeout(
        config.hello_timeout(),
        read_classification(client, config.limits.client_hello_max_bytes),
    )
    .await
    {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            metrics.parse_errors.inc();
            return Err(error);
        }
        Err(_) => {
            metrics.parse_errors.inc();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "ClientHello timeout",
            ));
        }
    };
    Ok((classification, buffered))
}

fn classify_target(
    classification: tls::Classification,
    config: &Config,
    metrics: &Metrics,
) -> ClassifiedTarget {
    match classification {
        tls::Classification::PlainHttp => {
            metrics.fallback_plain_http.inc();
            ClassifiedTarget::Fallback {
                target: config.fallbacks.plain_http,
                route_label: "plain_http",
            }
        }
        tls::Classification::Tls { sni: Some(sni) } => match config.routes.get(&sni) {
            Some(target) => {
                metrics.routed.inc();
                ClassifiedTarget::Routed {
                    target: target.upstream(),
                    socket_marks: target.socket_marks(),
                    route_label: sni,
                }
            }
            None => {
                metrics.fallback_unknown_sni.inc();
                ClassifiedTarget::Fallback {
                    target: config.fallbacks.unknown_sni,
                    route_label: "unknown_sni",
                }
            }
        },
        tls::Classification::Tls { sni: None } => {
            metrics.fallback_no_sni.inc();
            ClassifiedTarget::Fallback {
                target: config.fallbacks.no_sni,
                route_label: "no_sni",
            }
        }
    }
}

async fn proxy_classified(
    client: &mut TcpStream,
    upstream: ProxyUpstream<'_>,
    buffered: Vec<u8>,
    config: &Config,
    metrics: &Metrics,
    lifetime_timeout: Option<Duration>,
) -> io::Result<()> {
    let proxy = proxy_classified_unbounded(client, upstream, buffered, config, metrics);
    match lifetime_timeout {
        Some(deadline) => timeout(deadline, proxy).await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "fallback connection lifetime exceeded",
            )
        })?,
        None => proxy.await,
    }
}

async fn proxy_classified_unbounded(
    client: &mut TcpStream,
    upstream: ProxyUpstream<'_>,
    buffered: Vec<u8>,
    config: &Config,
    metrics: &Metrics,
) -> io::Result<()> {
    let diagnostics = upstream.diagnostics;
    if let Some(marks) = upstream.socket_marks {
        set_socket_mark(client, marks.download)?;
    }
    let mut upstream = match timeout(
        config.connect_timeout(),
        connect_upstream(
            upstream.address,
            upstream.socket_marks.map(|marks| marks.upload),
        ),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            metrics.record_connect_error(diagnostics.class, diagnostics.route_label);
            return Err(error);
        }
        Err(_) => {
            metrics.record_connect_error(diagnostics.class, diagnostics.route_label);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "upstream connect timeout",
            ));
        }
    };
    metrics.record_connect_success(diagnostics.class);
    upstream.set_nodelay(true)?;
    let classified_bytes = buffered.len() as u64;
    upstream.write_all(&buffered).await?;
    metrics.bytes_client_to_upstream.inc_by(classified_bytes);
    // `buffered` can reserve the configured maximum ClientHello size. Its
    // contents have been delivered and are no longer needed during the
    // potentially long-lived relay, so release that allocation explicitly.
    drop(buffered);
    let client_bytes = metrics.bytes_client_to_upstream.clone();
    let upstream_bytes = metrics.bytes_upstream_to_client.clone();
    splice::copy_bidirectional_buffered(
        client,
        &mut upstream,
        config.half_close_timeout(),
        move |bytes| client_bytes.inc_by(bytes),
        move |bytes| upstream_bytes.inc_by(bytes),
    )
    .await
}

async fn connect_upstream(target: SocketAddr, mark: Option<u32>) -> io::Result<TcpStream> {
    if mark.is_none() {
        return TcpStream::connect(target).await;
    }
    let socket = match target {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    set_socket_mark(&socket, mark.unwrap())?;
    socket.connect(target).await
}

fn set_socket_mark(socket: &impl AsRawFd, mark: u32) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const u32).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

async fn read_classification(
    client: &TcpStream,
    max_bytes: usize,
) -> io::Result<(tls::Classification, Vec<u8>)> {
    let mut buffer = Vec::with_capacity(INITIAL_BUFFER_CAPACITY.min(max_bytes));
    let mut classifier = tls::Classifier::new();
    loop {
        if buffer.len() >= max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello exceeds configured maximum",
            ));
        }
        client.readable().await?;
        let remaining = max_bytes - buffer.len();
        let chunk = remaining.min(16 * 1024);
        let mut read_buffer = [0u8; 16 * 1024];
        let result = client.try_read(&mut read_buffer[..chunk]);
        match result {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client closed before routing decision",
                ))
            }
            Ok(read) => {
                buffer.extend_from_slice(&read_buffer[..read]);
                match classifier.push(&read_buffer[..read]) {
                    Ok(tls::ParseProgress::Complete(classification)) => {
                        return Ok((classification, buffer));
                    }
                    Ok(tls::ParseProgress::NeedMore) => {}
                    Err(error) => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, error));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, net::Ipv4Addr};

    use super::*;
    use config::{Admission, Fallbacks, Limits};
    use tempfile::NamedTempFile;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn listener_backlog_can_be_raised_after_bind() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        set_listener_backlog(&listener, 25_000).unwrap();
    }

    #[test]
    fn source_admission_caps_canonical_ip_and_raii_releases() {
        let admission = Arc::new(SourceAdmission::new(1));
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let mapped = canonical_source_ip(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped()));
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8));

        let permit = admission.try_acquire(source).unwrap();
        assert_eq!(mapped, source);
        assert!(admission.try_acquire(mapped).is_none());
        let other_permit = admission.try_acquire(other).unwrap();
        drop(permit);
        assert!(admission.try_acquire(mapped).is_some());
        drop(other_permit);
    }

    fn config(route_target: SocketAddr, fallback: SocketAddr) -> Config {
        Config {
            bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            allow_redirect_ingress_bind: false,
            health_bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            routes: HashMap::from([(
                "example.test".to_string(),
                config::Route::Plain(route_target),
            )]),
            fallbacks: Fallbacks {
                unknown_sni: fallback,
                no_sni: fallback,
                plain_http: fallback,
            },
            admission: Admission::default(),
            limits: Limits::default(),
        }
    }

    fn tls_hello(hostname: &str) -> Vec<u8> {
        let name = hostname.as_bytes();
        let mut body = vec![3, 3];
        body.extend([7; 32]);
        body.push(0);
        body.extend([0, 2, 0x13, 1, 1, 0]);
        let mut extension = Vec::new();
        extension.extend(((name.len() + 3) as u16).to_be_bytes());
        extension.push(0);
        extension.extend((name.len() as u16).to_be_bytes());
        extension.extend(name);
        let mut extensions = Vec::new();
        extensions.extend(0u16.to_be_bytes());
        extensions.extend((extension.len() as u16).to_be_bytes());
        extensions.extend(extension);
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        let mut handshake = vec![1, 0, 0, body.len() as u8];
        handshake.extend(body);
        let mut record = vec![22, 3, 3];
        record.extend((handshake.len() as u16).to_be_bytes());
        record.extend(handshake);
        record
    }

    async fn echo_listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address)
    }

    #[tokio::test]
    async fn direct_relay_preserves_large_early_response_and_continuation() {
        const EARLY_RESPONSE_LEN: usize = 8 * 1024 + 37;
        let (backend, address) = echo_listener().await;
        tokio::spawn(async move {
            let (mut stream, _) = backend.accept().await.unwrap();
            let mut initial = [0u8; 4096];
            let _ = stream.read(&mut initial).await.unwrap();
            let response: Vec<u8> = (0..EARLY_RESPONSE_LEN)
                .map(|index| (index % 251) as u8)
                .collect();
            stream.write_all(&response).await.unwrap();
            let mut continuation = [0u8; TEST_EXCHANGE_BYTES];
            stream.read_exact(&mut continuation).await.unwrap();
            stream.write_all(&continuation).await.unwrap();
            let mut after_promotion = [0u8; 64];
            stream.read_exact(&mut after_promotion).await.unwrap();
            stream.write_all(&after_promotion).await.unwrap();
        });
        let fallback = tagged_backend(b"fallback").await;
        let selected = config(address, fallback);
        let metrics = Metrics::new().unwrap();
        let task_metrics = metrics.clone();
        let (mut client, router_side) = connected_pair().await;
        let router = tokio::spawn(async move {
            handle_connection(router_side, Arc::new(selected), &task_metrics).await
        });
        client.write_all(&tls_hello("example.test")).await.unwrap();
        let mut response = vec![0; EARLY_RESPONSE_LEN];
        client.read_exact(&mut response).await.unwrap();
        let expected: Vec<u8> = (0..EARLY_RESPONSE_LEN)
            .map(|index| (index % 251) as u8)
            .collect();
        assert_eq!(response, expected);
        let continuation = [0x77; TEST_EXCHANGE_BYTES];
        client.write_all(&continuation).await.unwrap();
        let mut continuation_echo = [0; TEST_EXCHANGE_BYTES];
        client.read_exact(&mut continuation_echo).await.unwrap();
        assert_eq!(continuation_echo, continuation);
        tokio::time::sleep(Duration::from_millis(600)).await;
        let after_promotion = [0x88; 64];
        client.write_all(&after_promotion).await.unwrap();
        let mut echoed = [0; 64];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, after_promotion);
        client.shutdown().await.unwrap();
        assert!(timeout(Duration::from_secs(1), router)
            .await
            .unwrap()
            .unwrap()
            .is_ok());
        assert_eq!(metrics.routed.get(), 1);
    }

    #[tokio::test]
    async fn routes_fragmented_tls_bidirectionally() {
        let (backend, backend_address) = echo_listener().await;
        tokio::spawn(async move {
            let (mut stream, _) = backend.accept().await.unwrap();
            let mut data = [0u8; 4096];
            loop {
                let read = stream.read(&mut data).await.unwrap();
                if read == 0 {
                    break;
                }
                stream.write_all(&data[..read]).await.unwrap();
            }
        });

        let (fallback, fallback_address) = echo_listener().await;
        let fallback_task = tokio::spawn(async move { fallback.accept().await });
        let metrics = Metrics::new().unwrap();
        let (client_side, router_side) = connected_pair().await;
        let config = Arc::new(config(backend_address, fallback_address));
        let router = tokio::spawn(async move {
            handle_connection(router_side, config, &metrics)
                .await
                .unwrap();
        });

        let hello = tls_hello("example.test");
        let mut client = client_side;
        client.write_all(&hello[..9]).await.unwrap();
        tokio::task::yield_now().await;
        client.write_all(&hello[9..]).await.unwrap();
        client.write_all(b"payload").await.unwrap();
        let mut initial_response = vec![0; hello.len() + b"payload".len()];
        client.read_exact(&mut initial_response).await.unwrap();
        assert_eq!(
            initial_response,
            [hello.clone(), b"payload".to_vec()].concat()
        );
        let continuation = [0x5a; TEST_EXCHANGE_BYTES];
        client.write_all(&continuation).await.unwrap();
        let mut continued_response = [0; TEST_EXCHANGE_BYTES];
        client.read_exact(&mut continued_response).await.unwrap();
        assert_eq!(continued_response, continuation);
        client.shutdown().await.unwrap();
        router.await.unwrap();
        assert!(!fallback_task.is_finished());
        fallback_task.abort();
    }

    #[tokio::test]
    async fn plain_http_uses_fallback_and_health_is_http() {
        let (backend, backend_address) = echo_listener().await;
        let backend_task = tokio::spawn(async move { backend.accept().await });
        let (fallback, fallback_address) = echo_listener().await;
        tokio::spawn(async move {
            let (mut stream, _) = fallback.accept().await.unwrap();
            let mut data = Vec::new();
            stream.read_to_end(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });
        let metrics = Metrics::new().unwrap();
        let (client_side, router_side) = connected_pair().await;
        let config = Arc::new(config(backend_address, fallback_address));
        let router = tokio::spawn(async move {
            handle_connection(router_side, config, &metrics)
                .await
                .unwrap();
        });
        let mut client = client_side;
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        router.await.unwrap();
        assert_eq!(response, b"GET / HTTP/1.1\r\n\r\n");
        assert!(!backend_task.is_finished());
        backend_task.abort();
    }

    #[tokio::test]
    async fn fallback_saturation_does_not_consume_routed_capacity() {
        let routed_backend = tagged_backend(b"routed").await;
        let (fallback, fallback_address) = echo_listener().await;
        let fallback_task = tokio::spawn(async move {
            let (mut first, _) = fallback.accept().await.unwrap();
            let mut request = [0u8; 18];
            first.read_exact(&mut request).await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        let mut selected = config(routed_backend, fallback_address);
        selected.admission = Admission {
            pre_parse_max_connections: 2,
            routed_max_connections: 2,
            routed_max_connections_per_source: 2,
            fallback_max_connections: 1,
        };
        selected.limits.fallback_lifetime_timeout_ms = 5_000;
        let metrics = Metrics::new().unwrap();
        let admission = AdmissionControl::new(selected.admission, 5).unwrap();
        let config = Arc::new(selected);

        let (mut first_client, first_router) = connected_pair().await;
        let first_permit = Arc::clone(&admission.pre_parse)
            .try_acquire_owned()
            .unwrap();
        let first_metrics = metrics.clone();
        let first_config = Arc::clone(&config);
        let first_admission = Arc::new(admission);
        let first_admission_task = Arc::clone(&first_admission);
        metrics.active_pre_parse.inc();
        let first = tokio::spawn(async move {
            handle_connection_admitted(
                first_router,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                first_config,
                &first_metrics,
                &first_admission_task,
                first_permit,
            )
            .await
        });
        first_client
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        for _ in 0..100 {
            if metrics.active_fallback.get() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(metrics.active_fallback.get(), 1);
        assert!(first_admission
            .routed_sources
            .active
            .lock()
            .unwrap()
            .is_empty());

        let (mut rejected_client, rejected_router) = connected_pair().await;
        let rejected_permit = Arc::clone(&first_admission.pre_parse)
            .try_acquire_owned()
            .unwrap();
        metrics.active_pre_parse.inc();
        let rejected = handle_connection_admitted(
            rejected_router,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Arc::clone(&config),
            &metrics,
            &first_admission,
            rejected_permit,
        );
        rejected_client
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(
            rejected.await.unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(metrics.rejected_fallback.get(), 1);

        let (mut routed_client, routed_router) = connected_pair().await;
        let routed_permit = Arc::clone(&first_admission.pre_parse)
            .try_acquire_owned()
            .unwrap();
        metrics.active_pre_parse.inc();
        let routed_metrics = metrics.clone();
        let routed_config = Arc::clone(&config);
        let routed_admission = Arc::clone(&first_admission);
        let routed = tokio::spawn(async move {
            handle_connection_admitted(
                routed_router,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                routed_config,
                &routed_metrics,
                &routed_admission,
                routed_permit,
            )
            .await
        });
        routed_client
            .write_all(&tls_hello("example.test"))
            .await
            .unwrap();
        let mut response = [0u8; TEST_EXCHANGE_BYTES];
        timeout(
            Duration::from_secs(1),
            routed_client.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response, repeated_tag(b"routed").as_slice());
        routed_client
            .write_all(&[0x33; TEST_EXCHANGE_BYTES])
            .await
            .unwrap();
        routed_client.shutdown().await.unwrap();
        assert!(timeout(Duration::from_secs(1), routed)
            .await
            .unwrap()
            .unwrap()
            .is_ok());

        first.abort();
        let _ = first.await;
        fallback_task.abort();
        let _ = fallback_task.await;
    }

    #[tokio::test]
    async fn fallback_lifetime_is_bounded_but_routed_connection_stays_open() {
        let (routed_backend, routed_address) = echo_listener().await;
        tokio::spawn(async move {
            let (mut stream, _) = routed_backend.accept().await.unwrap();
            let mut input = [0u8; 4096];
            loop {
                let read = stream.read(&mut input).await.unwrap();
                if read == 0 {
                    break;
                }
                stream.write_all(&input[..read]).await.unwrap();
            }
        });
        let (fallback, fallback_address) = echo_listener().await;
        tokio::spawn(async move {
            let (mut stream, _) = fallback.accept().await.unwrap();
            let mut input = [0u8; 4096];
            let _ = stream.read(&mut input).await;
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        let mut selected = config(routed_address, fallback_address);
        selected.limits.fallback_lifetime_timeout_ms = 50;
        let metrics = Metrics::new().unwrap();

        let (mut fallback_client, fallback_router) = connected_pair().await;
        let fallback_config = Arc::new(selected.clone());
        let fallback_metrics = metrics.clone();
        let fallback_proxy = tokio::spawn(async move {
            handle_connection(fallback_router, fallback_config, &fallback_metrics).await
        });
        fallback_client
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), fallback_proxy)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );

        let (mut routed_client, routed_router) = connected_pair().await;
        let routed_config = Arc::new(selected);
        let routed_metrics = metrics.clone();
        let routed_proxy = tokio::spawn(async move {
            handle_connection(routed_router, routed_config, &routed_metrics).await
        });
        let hello = tls_hello("example.test");
        routed_client.write_all(&hello).await.unwrap();
        let mut echoed = vec![0; hello.len()];
        routed_client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, hello);
        let continuation = [0x6b; TEST_EXCHANGE_BYTES];
        routed_client.write_all(&continuation).await.unwrap();
        let mut continuation_echo = [0; TEST_EXCHANGE_BYTES];
        routed_client
            .read_exact(&mut continuation_echo)
            .await
            .unwrap();
        assert_eq!(continuation_echo, continuation);
        tokio::time::sleep(Duration::from_millis(100)).await;
        routed_client.write_all(b"still-open").await.unwrap();
        let mut response = [0u8; 10];
        routed_client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"still-open");
        routed_client.shutdown().await.unwrap();
        assert!(timeout(Duration::from_secs(1), routed_proxy)
            .await
            .unwrap()
            .unwrap()
            .is_ok());
    }

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    async fn tagged_backend(tag: &'static [u8]) -> SocketAddr {
        let (listener, address) = echo_listener().await;
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut input = [0u8; 4096];
                    let _ = stream.read(&mut input).await;
                    let mut response = Vec::with_capacity(TEST_EXCHANGE_BYTES);
                    while response.len() < TEST_EXCHANGE_BYTES {
                        response.extend_from_slice(tag);
                    }
                    response.truncate(TEST_EXCHANGE_BYTES);
                    let _ = stream.write_all(&response).await;
                    let _ = stream.read(&mut input).await;
                });
            }
        });
        address
    }

    fn repeated_tag(tag: &[u8]) -> Vec<u8> {
        let mut response = Vec::with_capacity(TEST_EXCHANGE_BYTES);
        while response.len() < TEST_EXCHANGE_BYTES {
            response.extend_from_slice(tag);
        }
        response.truncate(TEST_EXCHANGE_BYTES);
        response
    }

    fn config_json(route: SocketAddr, fallback: SocketAddr) -> String {
        format!(
            r#"{{
              "bind":"127.0.0.1:18443",
              "health_bind":"127.0.0.1:19090",
              "routes":{{"example.test":"{route}"}},
              "fallbacks":{{"unknown_sni":"{fallback}","no_sni":"{fallback}","plain_http":"{fallback}"}}
            }}"#
        )
    }

    #[tokio::test]
    async fn sighup_reloads_routes_and_rejects_invalid_config() {
        let old_backend = tagged_backend(b"old").await;
        let new_backend = tagged_backend(b"new").await;
        let fallback = tagged_backend(b"fallback").await;
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), config_json(old_backend, fallback)).unwrap();

        let mut initial = Config::from_path(file.path()).unwrap();
        initial.bind.set_port(0);
        initial.health_bind.set_port(0);
        let (ready_tx, mut ready_rx) = mpsc::channel(1);
        let path = file.path().to_path_buf();
        let server = tokio::spawn(async move {
            run_with_limit(
                path,
                initial,
                Some(ready_tx),
                DEFAULT_MAX_CONCURRENT_CONNECTIONS,
            )
            .await
        });
        let (address, health_address) = ready_rx.recv().await.unwrap();

        let response = request_tls(address).await;
        assert_eq!(response, repeated_tag(b"old"));
        assert!(health_get(health_address, "/healthz")
            .await
            .starts_with(b"HTTP/1.1 200 OK"));

        let running_config = format!(
            r#"{{
              "bind":"{address}",
              "health_bind":"{health_address}",
              "routes":{{"example.test":"{new_backend}"}},
              "fallbacks":{{"unknown_sni":"{fallback}","no_sni":"{fallback}","plain_http":"{fallback}"}}
            }}"#
        );
        fs::write(file.path(), &running_config).unwrap();
        unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
        wait_for_response(address, &repeated_tag(b"new")).await;

        fs::write(file.path(), b"not json").unwrap();
        unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(request_tls(address).await, repeated_tag(b"new"));

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn sighup_rejects_admission_limit_changes() {
        let old_backend = tagged_backend(b"old").await;
        let new_backend = tagged_backend(b"new").await;
        let fallback = tagged_backend(b"fallback").await;
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), config_json(old_backend, fallback)).unwrap();

        let mut initial = Config::from_path(file.path()).unwrap();
        initial.bind.set_port(0);
        initial.health_bind.set_port(0);
        let (ready_tx, mut ready_rx) = mpsc::channel(1);
        let path = file.path().to_path_buf();
        let server =
            tokio::spawn(
                async move { run_with_limit(path, initial, Some(ready_tx), 40_000).await },
            );
        let (address, health_address) = ready_rx.recv().await.unwrap();
        assert_eq!(request_tls(address).await, repeated_tag(b"old"));

        let changed = format!(
            r#"{{
              "bind":"{address}",
              "health_bind":"{health_address}",
              "routes":{{"example.test":"{new_backend}"}},
              "fallbacks":{{"unknown_sni":"{fallback}","no_sni":"{fallback}","plain_http":"{fallback}"}},
              "admission":{{"pre_parse_max_connections":2047,"routed_max_connections":36001,"fallback_max_connections":256}}
            }}"#
        );
        fs::write(file.path(), changed).unwrap();
        unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(request_tls(address).await, repeated_tag(b"old"));

        server.abort();
        let _ = server.await;
    }

    async fn request_tls(address: SocketAddr) -> Vec<u8> {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(&tls_hello("example.test")).await.unwrap();
        let mut proof = [0u8; TEST_EXCHANGE_BYTES];
        stream.read_exact(&mut proof).await.unwrap();
        stream
            .write_all(&[0x42; TEST_EXCHANGE_BYTES])
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut output = proof.to_vec();
        stream.read_to_end(&mut output).await.unwrap();
        output
    }

    async fn wait_for_response(address: SocketAddr, expected: &[u8]) {
        for _ in 0..100 {
            if request_tls(address).await == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("route did not reload");
    }

    async fn health_get(address: SocketAddr, path: &str) -> Vec<u8> {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    }

    #[test]
    fn config_file_check_contract_is_valid() {
        let file = NamedTempFile::new().unwrap();
        fs::write(
            file.path(),
            r#"{
              "bind":"127.0.0.1:18443",
              "health_bind":"127.0.0.1:19090",
              "routes":{"example.test":"127.0.0.1:57270"},
              "fallbacks":{"unknown_sni":"127.0.0.1:4443","no_sni":"127.0.0.1:4443","plain_http":"127.0.0.1:8080"}
            }"#,
        )
        .unwrap();
        assert!(Config::from_path(file.path()).is_ok());
    }
}
