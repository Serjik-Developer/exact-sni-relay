use std::{
    collections::HashSet,
    io,
    sync::{Arc, Mutex},
};

use prometheus::{Encoder, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

// Route labels come from validated exact hostnames (or one of the three fixed
// fallback labels). SIGHUP can nevertheless introduce an unlimited sequence
// of different routes over the lifetime of a process. Bound the retained
// label set so operational diagnostics cannot become a cardinality leak.
const MAX_RETAINED_CONNECT_ERROR_ROUTES: usize = 256;
const OVERFLOW_ROUTE_LABEL: &str = "__overflow__";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamClass {
    Routed,
    Fallback,
}

impl UpstreamClass {
    fn label(self) -> &'static str {
        match self {
            Self::Routed => "routed",
            Self::Fallback => "fallback",
        }
    }
}

#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    pub accepted: IntCounter,
    pub active: IntGauge,
    pub active_pre_parse: IntGauge,
    pub active_routed: IntGauge,
    pub active_routed_established: IntGauge,
    pub active_fallback: IntGauge,
    pub rejected_pre_parse: IntCounter,
    pub rejected_routed: IntCounter,
    pub rejected_routed_source: IntCounter,
    pub rejected_fallback: IntCounter,
    pub routed: IntCounter,
    pub fallback_unknown_sni: IntCounter,
    pub fallback_no_sni: IntCounter,
    pub fallback_plain_http: IntCounter,
    pub parse_errors: IntCounter,
    pub connect_errors: IntCounter,
    pub connect_successes: IntCounter,
    pub routed_connect_errors: IntCounter,
    pub routed_connect_successes: IntCounter,
    pub fallback_connect_errors: IntCounter,
    pub fallback_connect_successes: IntCounter,
    connect_errors_by_route: IntCounterVec,
    retained_connect_error_routes: Arc<Mutex<HashSet<String>>>,
    pub reload_success: IntCounter,
    pub reload_errors: IntCounter,
    pub bytes_client_to_upstream: IntCounter,
    pub bytes_upstream_to_client: IntCounter,
}

impl Metrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
        let metrics = Self {
            registry,
            accepted: IntCounter::new(
                "sni_router_connections_accepted_total",
                "Accepted connections",
            )?,
            active: IntGauge::new("sni_router_connections_active", "Active connections")?,
            active_pre_parse: IntGauge::new(
                "sni_router_connections_active_pre_parse",
                "Connections admitted while awaiting a routing decision",
            )?,
            active_routed: IntGauge::new(
                "sni_router_connections_active_routed",
                "Active exact-SNI routed connections",
            )?,
            active_routed_established: IntGauge::new(
                "sni_router_connections_active_routed_established",
                "Active exact-SNI connections admitted to the relay data path",
            )?,
            active_fallback: IntGauge::new(
                "sni_router_connections_active_fallback",
                "Active fallback connections",
            )?,
            rejected_pre_parse: IntCounter::new(
                "sni_router_admission_rejected_pre_parse_total",
                "Connections rejected because pre-parse admission was full",
            )?,
            rejected_routed: IntCounter::new(
                "sni_router_admission_rejected_routed_total",
                "Exact-SNI connections rejected because routed admission was full",
            )?,
            rejected_routed_source: IntCounter::new(
                "sni_router_admission_rejected_routed_source_total",
                "Exact-SNI connections rejected by the per-source active-session limit",
            )?,
            rejected_fallback: IntCounter::new(
                "sni_router_admission_rejected_fallback_total",
                "Fallback connections rejected because fallback admission was full",
            )?,
            routed: IntCounter::new(
                "sni_router_connections_routed_total",
                "Exact SNI route matches",
            )?,
            fallback_unknown_sni: IntCounter::new(
                "sni_router_fallback_unknown_sni_total",
                "Connections sent to the unknown-SNI fallback",
            )?,
            fallback_no_sni: IntCounter::new(
                "sni_router_fallback_no_sni_total",
                "TLS connections sent to the no-SNI fallback",
            )?,
            fallback_plain_http: IntCounter::new(
                "sni_router_fallback_plain_http_total",
                "Plain HTTP connections sent to its fallback",
            )?,
            parse_errors: IntCounter::new(
                "sni_router_parse_errors_total",
                "Rejected initial messages",
            )?,
            connect_errors: IntCounter::new(
                "sni_router_connect_errors_total",
                "Upstream connect failures",
            )?,
            connect_successes: IntCounter::new(
                "sni_router_connect_successes_total",
                "Successful upstream connections",
            )?,
            routed_connect_errors: IntCounter::new(
                "sni_router_routed_connect_errors_total",
                "Upstream connect failures for exact-SNI routes",
            )?,
            routed_connect_successes: IntCounter::new(
                "sni_router_routed_connect_successes_total",
                "Successful upstream connections for exact-SNI routes",
            )?,
            fallback_connect_errors: IntCounter::new(
                "sni_router_fallback_connect_errors_total",
                "Upstream connect failures for fallback routes",
            )?,
            fallback_connect_successes: IntCounter::new(
                "sni_router_fallback_connect_successes_total",
                "Successful upstream connections for fallback routes",
            )?,
            connect_errors_by_route: IntCounterVec::new(
                Opts::new(
                    "sni_router_connect_errors_by_route_total",
                    "Upstream connect failures by bounded route label and traffic class",
                ),
                &["class", "route"],
            )?,
            retained_connect_error_routes: Arc::new(Mutex::new(HashSet::new())),
            reload_success: IntCounter::new(
                "sni_router_reload_success_total",
                "Successful SIGHUP reloads",
            )?,
            reload_errors: IntCounter::new(
                "sni_router_reload_errors_total",
                "Rejected SIGHUP reloads",
            )?,
            bytes_client_to_upstream: IntCounter::new(
                "sni_router_bytes_client_to_upstream_total",
                "Bytes relayed from clients to upstreams",
            )?,
            bytes_upstream_to_client: IntCounter::new(
                "sni_router_bytes_upstream_to_client_total",
                "Bytes relayed from upstreams to clients",
            )?,
        };
        metrics
            .registry
            .register(Box::new(metrics.accepted.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.active.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.active_pre_parse.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.active_routed.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.active_routed_established.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.active_fallback.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.rejected_pre_parse.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.rejected_routed.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.rejected_routed_source.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.rejected_fallback.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.routed.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.fallback_unknown_sni.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.fallback_no_sni.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.fallback_plain_http.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.parse_errors.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.connect_errors.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.connect_successes.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.routed_connect_errors.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.routed_connect_successes.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.fallback_connect_errors.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.fallback_connect_successes.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.connect_errors_by_route.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.reload_success.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.reload_errors.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.bytes_client_to_upstream.clone()))?;
        metrics
            .registry
            .register(Box::new(metrics.bytes_upstream_to_client.clone()))?;
        Ok(metrics)
    }

    pub fn encode(&self) -> Result<Vec<u8>, prometheus::Error> {
        let mut output = Vec::new();
        TextEncoder::new().encode(&self.registry.gather(), &mut output)?;
        Ok(output)
    }

    pub fn record_connect_success(&self, class: UpstreamClass) {
        self.connect_successes.inc();
        match class {
            UpstreamClass::Routed => self.routed_connect_successes.inc(),
            UpstreamClass::Fallback => self.fallback_connect_successes.inc(),
        }
    }

    pub fn record_connect_error(&self, class: UpstreamClass, route: &str) {
        // Preserve the original aggregate counter for existing alerts and
        // dashboards while exposing class counters suitable for watchdogs.
        self.connect_errors.inc();
        match class {
            UpstreamClass::Routed => self.routed_connect_errors.inc(),
            UpstreamClass::Fallback => self.fallback_connect_errors.inc(),
        }

        let route = self.retained_route_label(class, route);
        self.connect_errors_by_route
            .with_label_values(&[class.label(), route])
            .inc();
    }

    fn retained_route_label<'a>(&self, class: UpstreamClass, route: &'a str) -> &'a str {
        let key = format!("{}\0{route}", class.label());
        let mut retained = self
            .retained_connect_error_routes
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if retained.contains(&key) {
            return route;
        }
        if retained.len() < MAX_RETAINED_CONNECT_ERROR_ROUTES {
            retained.insert(key);
            return route;
        }
        OVERFLOW_ROUTE_LABEL
    }
}

pub async fn serve(listener: TcpListener, metrics: Metrics) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let _ = serve_one(stream, metrics).await;
        });
    }
}

async fn serve_one(mut stream: TcpStream, metrics: Metrics) -> io::Result<()> {
    let mut request = [0u8; 1024];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut request))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "health request timeout"))??;
    let mut request_parts = request[..read].split(|byte| *byte == b' ');
    let method = request_parts.next().unwrap_or_default();
    let path = request_parts.next().unwrap_or_default();
    if method != b"GET" {
        let body = b"method not allowed\n";
        let header = format!(
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(body).await?;
        return stream.shutdown().await;
    }
    let (status, content_type, body) = if path == b"/healthz" {
        ("200 OK", "text/plain; charset=utf-8", b"ok\n".to_vec())
    } else if path == b"/metrics" {
        match metrics.encode() {
            Ok(body) => ("200 OK", "text/plain; version=0.0.4", body),
            Err(_) => (
                "500 Internal Server Error",
                "text/plain; charset=utf-8",
                b"metrics error\n".to_vec(),
            ),
        }
    } else {
        (
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found\n".to_vec(),
        )
    };
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_diagnostics_preserve_aggregate_and_split_classes() {
        let metrics = Metrics::new().unwrap();
        metrics.record_connect_success(UpstreamClass::Routed);
        metrics.record_connect_success(UpstreamClass::Fallback);
        metrics.record_connect_error(UpstreamClass::Routed, "service.example");
        metrics.record_connect_error(UpstreamClass::Fallback, "unknown_sni");

        assert_eq!(metrics.connect_successes.get(), 2);
        assert_eq!(metrics.connect_errors.get(), 2);
        assert_eq!(metrics.routed_connect_successes.get(), 1);
        assert_eq!(metrics.routed_connect_errors.get(), 1);
        assert_eq!(metrics.fallback_connect_successes.get(), 1);
        assert_eq!(metrics.fallback_connect_errors.get(), 1);

        let encoded = String::from_utf8(metrics.encode().unwrap()).unwrap();
        assert!(encoded.contains(
            "sni_router_connect_errors_by_route_total{class=\"routed\",route=\"service.example\"} 1"
        ));
        assert!(encoded.contains(
            "sni_router_connect_errors_by_route_total{class=\"fallback\",route=\"unknown_sni\"} 1"
        ));
    }

    #[test]
    fn connect_error_route_cardinality_is_bounded_across_reloads() {
        let metrics = Metrics::new().unwrap();
        for index in 0..(MAX_RETAINED_CONNECT_ERROR_ROUTES + 100) {
            metrics.record_connect_error(UpstreamClass::Routed, &format!("route-{index}.example"));
        }

        assert_eq!(
            metrics.retained_connect_error_routes.lock().unwrap().len(),
            MAX_RETAINED_CONNECT_ERROR_ROUTES
        );
        let encoded = String::from_utf8(metrics.encode().unwrap()).unwrap();
        assert!(encoded.contains(
            "sni_router_connect_errors_by_route_total{class=\"routed\",route=\"__overflow__\"} 100"
        ));
    }
}
