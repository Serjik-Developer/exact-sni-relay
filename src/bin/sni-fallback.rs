#![cfg(target_os = "linux")]

use std::{
    fs::File,
    io::{self, BufReader},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use clap::Parser;
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal::unix::{signal, SignalKind},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{timeout, timeout_at, Instant},
};
use tokio_rustls::{rustls, LazyConfigAcceptor};

#[derive(Debug, Parser)]
#[command(version, about = "Bounded loopback TLS fallback terminator")]
struct Args {
    #[arg(long)]
    listen: SocketAddr,
    #[arg(long)]
    backend: SocketAddr,
    #[arg(long)]
    cert: PathBuf,
    #[arg(long)]
    key: PathBuf,
    /// Allowed TLS SNI hostname. Repeat for certificate aliases.
    #[arg(long, required = true, value_parser = parse_allowed_sni)]
    allowed_sni: Vec<String>,
    /// Also accept proper subdomains of every --allowed-sni hostname.
    #[arg(long)]
    allow_subdomains: bool,
    #[arg(long, default_value = "127.0.0.1:19091")]
    metrics: SocketAddr,
    #[arg(long, default_value_t = 10)]
    drain_seconds: u64,
    /// Maximum number of simultaneous TLS fallback connections.
    #[arg(long, default_value_t = 4096, value_parser = parse_max_connections)]
    max_connections: usize,
    /// Maximum time allowed for a client TLS handshake.
    #[arg(long, default_value_t = 5000, value_parser = parse_timeout_ms)]
    handshake_timeout_ms: u64,
    /// Maximum time allowed for the loopback backend connect.
    #[arg(long, default_value_t = 1000, value_parser = parse_timeout_ms)]
    backend_connect_timeout_ms: u64,
    /// Tokio worker threads. Defaults to the runtime's available-CPU choice.
    #[arg(long, value_parser = parse_runtime_workers)]
    runtime_workers: Option<usize>,
    #[arg(long)]
    check_config: bool,
}

fn parse_allowed_sni(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return Err("allowed SNI must be a non-empty ASCII hostname".to_string());
    }
    let normalized = value.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("allowed SNI is not a valid DNS hostname".to_string());
    }
    Ok(normalized)
}

#[derive(Debug)]
struct SniPolicy {
    exact: Box<[String]>,
    allow_subdomains: bool,
}

impl SniPolicy {
    fn new(mut exact: Vec<String>, allow_subdomains: bool) -> Self {
        exact.sort_unstable();
        exact.dedup();
        Self {
            exact: exact.into_boxed_slice(),
            allow_subdomains,
        }
    }

    fn allows(&self, candidate: Option<&str>) -> bool {
        let Some(candidate) = candidate else {
            return false;
        };
        self.exact.iter().any(|allowed| {
            candidate.eq_ignore_ascii_case(allowed)
                || (self.allow_subdomains
                    && candidate.len() > allowed.len()
                    && candidate.as_bytes()[candidate.len() - allowed.len() - 1] == b'.'
                    && candidate[candidate.len() - allowed.len()..].eq_ignore_ascii_case(allowed))
        })
    }
}

fn parse_max_connections(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "max-connections must be an integer".to_string())?;
    if (1..=1_000_000).contains(&parsed) {
        Ok(parsed)
    } else {
        Err("max-connections must be between 1 and 1000000".to_string())
    }
}

fn parse_timeout_ms(value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| "timeout must be an integer number of milliseconds".to_string())?;
    if (1..=300_000).contains(&parsed) {
        Ok(parsed)
    } else {
        Err("timeout must be between 1 and 300000 milliseconds".to_string())
    }
}

fn parse_runtime_workers(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "runtime-workers must be an integer".to_string())?;
    if (1..=256).contains(&parsed) {
        Ok(parsed)
    } else {
        Err("runtime-workers must be between 1 and 256".to_string())
    }
}

fn build_runtime(worker_threads: Option<usize>) -> io::Result<tokio::runtime::Runtime> {
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.enable_all();
    if let Some(worker_threads) = worker_threads {
        runtime.worker_threads(worker_threads);
    }
    runtime.build()
}

#[derive(Clone)]
struct Metrics {
    registry: Registry,
    accepted: IntCounter,
    admission_rejected: IntCounter,
    active: IntGauge,
    handshake_errors: IntCounter,
    handshake_timeouts: IntCounter,
    sni_rejected: IntCounter,
    backend_errors: IntCounter,
    backend_connect_timeouts: IntCounter,
    reload_success: IntCounter,
    reload_failure: IntCounter,
    graceful_shutdowns: IntCounter,
    forced_shutdown_connections: IntCounter,
}

impl Metrics {
    fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
        let metrics = Self {
            registry,
            accepted: IntCounter::new(
                "sni_fallback_connections_accepted_total",
                "Accepted TLS fallback connections",
            )?,
            admission_rejected: IntCounter::new(
                "sni_fallback_admission_rejected_total",
                "Connections rejected before task allocation because the admission limit was full",
            )?,
            active: IntGauge::new(
                "sni_fallback_connections_active",
                "Active TLS fallback connections",
            )?,
            handshake_errors: IntCounter::new(
                "sni_fallback_handshake_errors_total",
                "Failed TLS handshakes",
            )?,
            handshake_timeouts: IntCounter::new(
                "sni_fallback_handshake_timeouts_total",
                "TLS handshakes closed after the configured deadline",
            )?,
            sni_rejected: IntCounter::new(
                "sni_fallback_sni_rejected_total",
                "ClientHello messages rejected before key exchange due to missing or foreign SNI",
            )?,
            backend_errors: IntCounter::new(
                "sni_fallback_backend_errors_total",
                "Backend connection or relay failures",
            )?,
            backend_connect_timeouts: IntCounter::new(
                "sni_fallback_backend_connect_timeouts_total",
                "Loopback backend connects closed after the configured deadline",
            )?,
            reload_success: IntCounter::new(
                "sni_fallback_certificate_reload_success_total",
                "Successful atomic SIGHUP certificate reloads",
            )?,
            reload_failure: IntCounter::new(
                "sni_fallback_certificate_reload_failure_total",
                "Rejected SIGHUP certificate reloads",
            )?,
            graceful_shutdowns: IntCounter::new(
                "sni_fallback_graceful_shutdown_total",
                "Graceful shutdowns requested",
            )?,
            forced_shutdown_connections: IntCounter::new(
                "sni_fallback_forced_shutdown_connections_total",
                "Connections aborted after the drain deadline",
            )?,
        };
        for collector in [
            Box::new(metrics.accepted.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(metrics.admission_rejected.clone()),
            Box::new(metrics.active.clone()),
            Box::new(metrics.handshake_errors.clone()),
            Box::new(metrics.handshake_timeouts.clone()),
            Box::new(metrics.sni_rejected.clone()),
            Box::new(metrics.backend_errors.clone()),
            Box::new(metrics.backend_connect_timeouts.clone()),
            Box::new(metrics.reload_success.clone()),
            Box::new(metrics.reload_failure.clone()),
            Box::new(metrics.graceful_shutdowns.clone()),
            Box::new(metrics.forced_shutdown_connections.clone()),
        ] {
            metrics.registry.register(collector)?;
        }
        Ok(metrics)
    }

    fn render(&self) -> io::Result<Vec<u8>> {
        let mut body = Vec::new();
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut body)
            .map_err(io::Error::other)?;
        Ok(body)
    }
}

struct ActiveGuard<'a>(&'a IntGauge);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.dec();
    }
}

struct ProxySettings {
    backend: SocketAddr,
    sni_policy: SniPolicy,
    tls_config: ArcSwap<rustls::ServerConfig>,
    handshake_deadline: Duration,
    backend_connect_deadline: Duration,
}

fn is_benign_relay_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

#[derive(Debug, PartialEq, Eq)]
enum HandshakeFailure {
    Protocol,
    Timeout,
    SniRejected,
}

async fn accept_allowed_tls(
    stream: TcpStream,
    tls_config: &ArcSwap<rustls::ServerConfig>,
    sni_policy: &SniPolicy,
    deadline: Duration,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>, HandshakeFailure> {
    // LazyConfigAcceptor parses only enough of ClientHello to expose SNI. A
    // foreign or absent SNI is dropped before certificate signing/key exchange,
    // which keeps scanner floods out of the expensive cryptographic path.
    let handshake_timeout_at = Instant::now() + deadline;
    let lazy = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    let start = match timeout_at(handshake_timeout_at, lazy).await {
        Ok(Ok(start)) => start,
        Ok(Err(_)) => return Err(HandshakeFailure::Protocol),
        Err(_) => return Err(HandshakeFailure::Timeout),
    };
    if !sni_policy.allows(start.client_hello().server_name()) {
        return Err(HandshakeFailure::SniRejected);
    }
    // Load the current certificate only for an allowed ClientHello. This
    // avoids an ArcSwap/Arc refcount operation for scanners and foreign SNI.
    match timeout_at(
        handshake_timeout_at,
        start.into_stream(tls_config.load_full()),
    )
    .await
    {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(_)) => Err(HandshakeFailure::Protocol),
        Err(_) => Err(HandshakeFailure::Timeout),
    }
}

fn ensure_loopback(name: &str, address: SocketAddr) -> io::Result<()> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be a literal loopback address"),
        ))
    }
}

fn load_tls_config(cert_path: &Path, key_path: &Path) -> io::Result<rustls::ServerConfig> {
    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate file contains no certificates",
        ));
    }

    let mut key_reader = BufReader::new(File::open(key_path)?);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "key file contains no key"))?;

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn reload_certificate(
    config: &ArcSwap<rustls::ServerConfig>,
    cert_path: &Path,
    key_path: &Path,
    metrics: &Metrics,
) -> io::Result<()> {
    // Parsing and cert/key consistency validation happen before ArcSwap. A
    // partial or mismatched renewal can therefore never replace the serving
    // configuration, while established TLS streams keep their existing Arc.
    match load_tls_config(cert_path, key_path) {
        Ok(reloaded) => {
            config.store(Arc::new(reloaded));
            metrics.reload_success.inc();
            Ok(())
        }
        Err(error) => {
            metrics.reload_failure.inc();
            Err(error)
        }
    }
}

async fn proxy(
    stream: TcpStream,
    settings: Arc<ProxySettings>,
    metrics: Arc<Metrics>,
    _admission: OwnedSemaphorePermit,
) {
    metrics.active.inc();
    let _active = ActiveGuard(&metrics.active);
    // Fallback traffic is interactive and dominated by small TLS/HTTP
    // records. Avoid delayed ACK/Nagle coupling on both loopback legs.
    let _ = stream.set_nodelay(true);
    let mut tls = match accept_allowed_tls(
        stream,
        &settings.tls_config,
        &settings.sni_policy,
        settings.handshake_deadline,
    )
    .await
    {
        Ok(stream) => stream,
        Err(HandshakeFailure::Protocol) => {
            metrics.handshake_errors.inc();
            return;
        }
        Err(HandshakeFailure::Timeout) => {
            metrics.handshake_timeouts.inc();
            return;
        }
        Err(HandshakeFailure::SniRejected) => {
            metrics.sni_rejected.inc();
            return;
        }
    };
    let mut upstream = match timeout(
        settings.backend_connect_deadline,
        TcpStream::connect(settings.backend),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => {
            metrics.backend_errors.inc();
            return;
        }
        Err(_) => {
            metrics.backend_connect_timeouts.inc();
            return;
        }
    };
    let _ = upstream.set_nodelay(true);
    if let Err(error) = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await {
        // A TLS peer closing without close_notify after receiving the complete
        // response is normal on the public Internet. Count only errors that
        // indicate a real backend/relay fault; otherwise the counter becomes
        // a client-disconnect counter and cannot drive a safe watchdog.
        if !is_benign_relay_error(&error) {
            metrics.backend_errors.inc();
        }
    }
    // copy_bidirectional already shuts each writer down after that direction
    // reaches EOF. On an I/O error, dropping both owned streams is the only
    // useful cleanup; repeating shutdown here only adds work per connection.
}

async fn serve_metrics(listener: TcpListener, metrics: Arc<Metrics>) -> io::Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let mut request = [0_u8; 2048];
            let _ = timeout(Duration::from_secs(2), stream.read(&mut request)).await;
            let body = match metrics.render() {
                Ok(body) => body,
                Err(_) => return,
            };
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.shutdown().await;
        });
    }
}

async fn drain_connections(connections: &mut JoinSet<()>, deadline: Duration, metrics: &Metrics) {
    if timeout(deadline, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        metrics
            .forced_shutdown_connections
            .inc_by(connections.len() as u64);
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

async fn run(args: Args, initial: rustls::ServerConfig) -> io::Result<()> {
    ensure_loopback("listen", args.listen)?;
    ensure_loopback("backend", args.backend)?;
    ensure_loopback("metrics", args.metrics)?;
    let listener = TcpListener::bind(args.listen).await?;
    let metrics_listener = TcpListener::bind(args.metrics).await?;
    let metrics = Arc::new(Metrics::new().map_err(io::Error::other)?);
    let admission = Arc::new(Semaphore::new(args.max_connections));
    let proxy_settings = Arc::new(ProxySettings {
        backend: args.backend,
        sni_policy: SniPolicy::new(args.allowed_sni, args.allow_subdomains),
        tls_config: ArcSwap::from_pointee(initial),
        handshake_deadline: Duration::from_millis(args.handshake_timeout_ms),
        backend_connect_deadline: Duration::from_millis(args.backend_connect_timeout_ms),
    });
    let mut metrics_task = tokio::spawn(serve_metrics(metrics_listener, Arc::clone(&metrics)));
    let mut connections = JoinSet::new();
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                metrics.accepted.inc();
                let permit = match Arc::clone(&admission).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        // Drop the socket without allocating a connection task or
                        // entering rustls. Kernel backpressure then protects the
                        // process during scanner/handshake floods.
                        metrics.admission_rejected.inc();
                        continue;
                    }
                };
                connections.spawn(proxy(
                    stream,
                    Arc::clone(&proxy_settings),
                    Arc::clone(&metrics),
                    permit,
                ));
            }
            _ = sighup.recv() => {
                if let Err(error) = reload_certificate(
                    &proxy_settings.tls_config,
                    &args.cert,
                    &args.key,
                    &metrics,
                ) {
                    eprintln!("certificate reload rejected; previous certificate retained: {error}");
                }
            }
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    eprintln!("fallback connection task failed: {error}");
                }
            }
        }
    }

    // Dropping the listener stops new accepts. Existing streams are owned by
    // the JoinSet and drain independently until the explicit deadline.
    drop(listener);
    metrics.graceful_shutdowns.inc();
    metrics_task.abort();
    let _ = (&mut metrics_task).await;
    drain_connections(
        &mut connections,
        Duration::from_secs(args.drain_seconds),
        &metrics,
    )
    .await;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    ensure_loopback("listen", args.listen)?;
    ensure_loopback("backend", args.backend)?;
    ensure_loopback("metrics", args.metrics)?;
    let config = load_tls_config(&args.cert, &args.key)?;
    if args.check_config {
        println!("configuration and certificate are valid");
        return Ok(());
    }
    let runtime = build_runtime(args.runtime_workers)?;
    runtime.block_on(run(args, config))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpStream as StdTcpStream,
        process::Command,
        sync::mpsc,
    };
    use tempfile::tempdir;

    fn write_certificate(cert: &Path, key: &Path, common_name: &str) {
        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                &format!("/CN={common_name}"),
                "-keyout",
            ])
            .arg(key)
            .arg("-out")
            .arg(cert)
            .output()
            .expect("openssl is required for TLS fallback tests");
        assert!(status.status.success());
    }

    fn client_hello(server_name: &str, enable_sni: bool) -> Vec<u8> {
        let mut config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
            .with_no_client_auth();
        config.enable_sni = enable_sni;
        let name = rustls::pki_types::ServerName::try_from(server_name.to_string()).unwrap();
        let mut connection = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        let mut hello = Vec::new();
        connection.write_tls(&mut hello).unwrap();
        hello
    }

    #[derive(Debug)]
    struct AcceptAnyCertificate;

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    async fn handshake_outcome(
        hello: Vec<u8>,
        chunk_size: usize,
        policy: SniPolicy,
        handshake_timeout: Duration,
    ) -> HandshakeFailure {
        let directory = tempdir().unwrap();
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        write_certificate(&cert, &key, "allowed.test");
        let config = ArcSwap::from_pointee(load_tls_config(&cert, &key).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (result_tx, result_rx) = mpsc::channel();
        let client = std::thread::spawn(move || {
            let mut client = StdTcpStream::connect(address).unwrap();
            for chunk in hello.chunks(chunk_size) {
                client.write_all(chunk).unwrap();
            }
            // Foreign/no-SNI is rejected immediately after ClientHello. For
            // an allowed SNI this EOF turns the remaining crypto stage into a
            // protocol error, proving it passed the SNI gate.
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut response = Vec::new();
            let _ = client.read_to_end(&mut response);
            result_tx.send(()).unwrap();
        });
        let (server, _) = listener.accept().await.unwrap();
        let failure = accept_allowed_tls(server, &config, &policy, handshake_timeout)
            .await
            .expect_err("partial handshake must not complete");
        result_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        client.join().unwrap();
        failure
    }

    async fn full_handshake(version: &'static rustls::SupportedProtocolVersion) {
        let directory = tempdir().unwrap();
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        write_certificate(&cert, &key, "allowed.test");
        let server_config = ArcSwap::from_pointee(load_tls_config(&cert, &key).unwrap());
        let client_config = rustls::ClientConfig::builder_with_protocol_versions(&[version])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
            .with_no_client_auth();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept_allowed_tls(
                stream,
                &server_config,
                &SniPolicy::new(vec!["allowed.test".to_string()], false),
                Duration::from_secs(2),
            )
            .await
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("allowed.test").unwrap();
        let client_result = tokio_rustls::TlsConnector::from(Arc::new(client_config))
            .connect(server_name, stream)
            .await;
        assert!(client_result.is_ok());
        assert!(server.await.unwrap().is_ok());
    }

    #[test]
    fn runtime_worker_override_is_bounded_and_buildable() {
        assert_eq!(parse_runtime_workers("1").unwrap(), 1);
        assert_eq!(parse_runtime_workers("4").unwrap(), 4);
        assert_eq!(parse_runtime_workers("256").unwrap(), 256);
        assert!(parse_runtime_workers("0").is_err());
        assert!(parse_runtime_workers("257").is_err());
        assert!(parse_runtime_workers("workers").is_err());
        let runtime = build_runtime(Some(2)).expect("two-worker runtime must build");
        assert_eq!(runtime.block_on(async { 42 }), 42);
    }

    #[test]
    fn overload_and_timeout_limits_are_bounded() {
        assert_eq!(parse_max_connections("1").unwrap(), 1);
        assert_eq!(parse_max_connections("4096").unwrap(), 4096);
        assert_eq!(parse_max_connections("1000000").unwrap(), 1_000_000);
        assert!(parse_max_connections("0").is_err());
        assert!(parse_max_connections("1000001").is_err());
        assert!(parse_max_connections("many").is_err());

        assert_eq!(parse_timeout_ms("1").unwrap(), 1);
        assert_eq!(parse_timeout_ms("5000").unwrap(), 5000);
        assert_eq!(parse_timeout_ms("300000").unwrap(), 300_000);
        assert!(parse_timeout_ms("0").is_err());
        assert!(parse_timeout_ms("300001").is_err());
        assert!(parse_timeout_ms("later").is_err());
    }

    #[test]
    fn expected_peer_disconnects_are_not_backend_failures() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::NotConnected,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(is_benign_relay_error(&io::Error::from(kind)));
        }
        assert!(!is_benign_relay_error(&io::Error::from(
            io::ErrorKind::TimedOut
        )));
        assert!(!is_benign_relay_error(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }

    #[test]
    fn sni_policy_is_exact_by_default_and_normalizes_configuration() {
        assert_eq!(parse_allowed_sni("Example.COM.").unwrap(), "example.com");
        for invalid in ["", ".", "a..b", "-bad.test", "bad-.test", "bad_name"] {
            assert!(parse_allowed_sni(invalid).is_err(), "accepted {invalid:?}");
        }
        let policy = SniPolicy::new(vec!["example.com".to_string()], false);
        assert!(policy.allows(Some("EXAMPLE.COM")));
        assert!(!policy.allows(Some("www.example.com")));
        assert!(!policy.allows(Some("notexample.com")));
        assert!(!policy.allows(None));
    }

    #[test]
    fn subdomain_policy_requires_a_dns_label_boundary() {
        let policy = SniPolicy::new(vec!["example.com".to_string()], true);
        assert!(policy.allows(Some("example.com")));
        assert!(policy.allows(Some("a.example.com")));
        assert!(policy.allows(Some("A.B.Example.Com")));
        assert!(!policy.allows(Some("notexample.com")));
        assert!(!policy.allows(Some("example.com.attacker.test")));
    }

    #[tokio::test]
    async fn fragmented_allowed_client_hello_reaches_crypto_stage() {
        let failure = handshake_outcome(
            client_hello("allowed.test", true),
            1,
            SniPolicy::new(vec!["allowed.test".to_string()], false),
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(failure, HandshakeFailure::Protocol);
    }

    #[tokio::test]
    async fn allowed_sni_completes_tls12_and_tls13() {
        full_handshake(&rustls::version::TLS12).await;
        full_handshake(&rustls::version::TLS13).await;
    }

    #[tokio::test]
    async fn foreign_and_missing_sni_are_rejected_before_crypto() {
        for hello in [
            client_hello("foreign.test", true),
            client_hello("allowed.test", false),
        ] {
            let failure = handshake_outcome(
                hello,
                usize::MAX,
                SniPolicy::new(vec!["allowed.test".to_string()], false),
                Duration::from_secs(2),
            )
            .await;
            assert_eq!(failure, HandshakeFailure::SniRejected);
        }
    }

    #[tokio::test]
    async fn malformed_tls_is_a_protocol_error() {
        let failure = handshake_outcome(
            b"definitely not a TLS ClientHello".to_vec(),
            usize::MAX,
            SniPolicy::new(vec!["allowed.test".to_string()], false),
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(failure, HandshakeFailure::Protocol);
    }

    #[tokio::test]
    async fn silent_client_hits_the_single_handshake_deadline() {
        let directory = tempdir().unwrap();
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        write_certificate(&cert, &key, "allowed.test");
        let config = ArcSwap::from_pointee(load_tls_config(&cert, &key).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(TcpStream::connect(address));
        let (server, _) = listener.accept().await.unwrap();
        let client = client.await.unwrap().unwrap();
        let started = Instant::now();
        let failure = accept_allowed_tls(
            server,
            &config,
            &SniPolicy::new(vec!["allowed.test".to_string()], false),
            Duration::from_millis(20),
        )
        .await
        .expect_err("silent client must time out");
        assert_eq!(failure, HandshakeFailure::Timeout);
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(client);
    }

    #[tokio::test]
    async fn admission_permit_is_held_until_connection_finishes() {
        let admission = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&admission).try_acquire_owned().unwrap();
        assert!(Arc::clone(&admission).try_acquire_owned().is_err());
        drop(permit);
        assert!(Arc::clone(&admission).try_acquire_owned().is_ok());
    }

    #[test]
    fn invalid_reload_is_atomic_and_counted() {
        let directory = tempdir().unwrap();
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        write_certificate(&cert, &key, "first.invalid");
        let initial = Arc::new(load_tls_config(&cert, &key).unwrap());
        let current = ArcSwap::from(Arc::clone(&initial));
        let metrics = Metrics::new().unwrap();

        std::fs::write(&key, "not a private key").unwrap();
        assert!(reload_certificate(&current, &cert, &key, &metrics).is_err());
        assert!(Arc::ptr_eq(&initial, &current.load_full()));
        assert_eq!(metrics.reload_success.get(), 0);
        assert_eq!(metrics.reload_failure.get(), 1);
    }

    #[test]
    fn valid_reload_swaps_only_after_validation() {
        let directory = tempdir().unwrap();
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        write_certificate(&cert, &key, "first.invalid");
        let initial = Arc::new(load_tls_config(&cert, &key).unwrap());
        let current = ArcSwap::from(Arc::clone(&initial));
        let metrics = Metrics::new().unwrap();

        write_certificate(&cert, &key, "second.invalid");
        reload_certificate(&current, &cert, &key, &metrics).unwrap();
        assert!(!Arc::ptr_eq(&initial, &current.load_full()));
        assert_eq!(metrics.reload_success.get(), 1);
        assert_eq!(metrics.reload_failure.get(), 0);
    }

    #[tokio::test]
    async fn drain_waits_for_existing_connections() {
        let metrics = Metrics::new().unwrap();
        let mut connections = JoinSet::new();
        connections.spawn(async {
            tokio::time::sleep(Duration::from_millis(20)).await;
        });
        drain_connections(&mut connections, Duration::from_secs(1), &metrics).await;
        assert!(connections.is_empty());
        assert_eq!(metrics.forced_shutdown_connections.get(), 0);
    }

    #[tokio::test]
    async fn drain_aborts_only_after_deadline_and_counts_connections() {
        let metrics = Metrics::new().unwrap();
        let mut connections = JoinSet::new();
        connections.spawn(std::future::pending());
        connections.spawn(std::future::pending());
        drain_connections(&mut connections, Duration::from_millis(10), &metrics).await;
        assert!(connections.is_empty());
        assert_eq!(metrics.forced_shutdown_connections.get(), 2);
    }
}
