use std::{
    env,
    fs::File,
    io::{self, BufReader},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};

const HOST: &str = "fallback-bench.invalid";
const BODY: &[u8] = b"port-rental-fallback-benchmark-ok\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Content-Length: 34\r\n\
Connection: close\r\n\r\n\
port-rental-fallback-benchmark-ok\n";
const REQUEST: &[u8] = b"GET /health HTTP/1.1\r\n\
Host: fallback-bench.invalid\r\n\
Connection: close\r\n\r\n";
const MAX_CONCURRENCY: usize = 4096;
const MAX_DURATION_SECONDS: usize = 3600;

fn argument(name: &str) -> io::Result<String> {
    let mut arguments = env::args();
    while let Some(current) = arguments.next() {
        if current == name {
            return arguments.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("missing value for {name}"),
                )
            });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("missing {name}"),
    ))
}

fn bounded_usize(name: &str, maximum: usize) -> io::Result<usize> {
    let value = argument(name)?
        .parse::<usize>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if (1..=maximum).contains(&value) {
        Ok(value)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be between 1 and {maximum}"),
        ))
    }
}

fn loopback_address(name: &str) -> io::Result<SocketAddr> {
    let address = argument(name)?
        .parse::<SocketAddr>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if address.ip().is_loopback() {
        Ok(address)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be a literal loopback address"),
        ))
    }
}

async fn serve_backend() -> io::Result<()> {
    let listener = TcpListener::bind(loopback_address("--listen")?).await?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut request = [0_u8; 1024];
            if stream.read(&mut request).await.is_ok() {
                let _ = stream.write_all(RESPONSE).await;
            }
            let _ = stream.shutdown().await;
        });
    }
}

fn tls_config(certificate_path: &str) -> io::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let mut reader = BufReader::new(File::open(certificate_path)?);
    for certificate in rustls_pemfile::certs(&mut reader) {
        roots
            .add(certificate.map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
    }
    if roots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "certificate file contains no certificates",
        ));
    }

    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Every operation must perform a complete handshake. Disabling client
    // resumption prevents tickets or session IDs from changing the workload.
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

async fn one_request(
    connector: &TlsConnector,
    address: SocketAddr,
    server_name: ServerName<'static>,
) -> io::Result<()> {
    let stream = TcpStream::connect(address).await?;
    stream.set_nodelay(true)?;
    let mut tls = connector.connect(server_name, stream).await?;
    tls.write_all(REQUEST).await?;

    let mut response = Vec::with_capacity(256);
    loop {
        let mut buffer = [0_u8; 1024];
        match tls.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&buffer[..read]),
            // Some terminators close without TLS close_notify. The complete
            // deterministic response remains a successful HTTP exchange.
            Err(_) if response.windows(6).any(|part| part == b"200 OK") => break,
            Err(error) => return Err(error),
        }
    }
    if !response.windows(6).any(|part| part == b"200 OK") || !response.ends_with(BODY) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incorrect HTTP response",
        ));
    }
    Ok(())
}

async fn run_load() -> io::Result<()> {
    let address = loopback_address("--address")?;
    let certificate = argument("--cert")?;
    let concurrency = bounded_usize("--concurrency", MAX_CONCURRENCY)?;
    let duration = Duration::from_secs(bounded_usize("--duration", MAX_DURATION_SECONDS)? as u64);
    let connector = TlsConnector::from(Arc::new(tls_config(&certificate)?));
    let server_name = ServerName::try_from(HOST).map_err(io::Error::other)?;
    let successes = Arc::new(AtomicU64::new(0));
    let failures = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let deadline = start + duration;
    let mut workers = JoinSet::new();

    for _ in 0..concurrency {
        let connector = connector.clone();
        let server_name = server_name.clone();
        let successes = Arc::clone(&successes);
        let failures = Arc::clone(&failures);
        workers.spawn(async move {
            while Instant::now() < deadline {
                match timeout(
                    Duration::from_secs(3),
                    one_request(&connector, address, server_name.clone()),
                )
                .await
                {
                    Ok(Ok(())) => {
                        successes.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
    }
    while workers.join_next().await.is_some() {}

    let elapsed = start.elapsed().as_secs_f64();
    let successes = successes.load(Ordering::Relaxed);
    let failures = failures.load(Ordering::Relaxed);
    println!(
        "ok={successes} failed={failures} elapsed={elapsed:.6} rate={:.3}",
        successes as f64 / elapsed
    );
    if failures == 0 {
        Ok(())
    } else {
        Err(io::Error::other("one or more TLS requests failed"))
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    match env::args().nth(1).as_deref() {
        Some("backend") => serve_backend().await,
        Some("load") => run_load().await,
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: sni-tls-loadgen backend|load [options]",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_response_has_declared_length() {
        assert_eq!(BODY.len(), 34);
        assert!(RESPONSE.ends_with(BODY));
    }

    #[test]
    fn safety_bounds_are_finite() {
        assert_eq!(MAX_CONCURRENCY, 4096);
        assert_eq!(MAX_DURATION_SECONDS, 3600);
    }
}
