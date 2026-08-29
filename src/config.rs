use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};

use serde::{Deserialize, Deserializer};
use thiserror::Error;

const MIN_HELLO_BYTES: usize = 4 * 1024;
const MAX_HELLO_BYTES: usize = 256 * 1024;
const MAX_ADMISSION_CONNECTIONS: usize = 160_000;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    #[serde(default)]
    pub allow_redirect_ingress_bind: bool,
    pub health_bind: SocketAddr,
    pub routes: HashMap<String, Route>,
    pub fallbacks: Fallbacks,
    #[serde(default)]
    pub admission: Admission,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    pub pre_parse_max_connections: usize,
    pub routed_max_connections: usize,
    pub routed_max_connections_per_source: usize,
    pub fallback_max_connections: usize,
}

impl<'de> Deserialize<'de> for Admission {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireAdmission {
            #[serde(default = "default_pre_parse_max_connections")]
            pre_parse_max_connections: usize,
            #[serde(default = "default_routed_max_connections")]
            routed_max_connections: usize,
            #[serde(default = "default_routed_max_connections_per_source")]
            routed_max_connections_per_source: usize,
            #[serde(default = "default_fallback_max_connections")]
            fallback_max_connections: usize,
        }

        let wire = WireAdmission::deserialize(deserializer)?;
        Ok(Self {
            pre_parse_max_connections: wire.pre_parse_max_connections,
            routed_max_connections: wire.routed_max_connections,
            routed_max_connections_per_source: wire.routed_max_connections_per_source,
            fallback_max_connections: wire.fallback_max_connections,
        })
    }
}

impl Default for Admission {
    fn default() -> Self {
        Self {
            pre_parse_max_connections: default_pre_parse_max_connections(),
            routed_max_connections: default_routed_max_connections(),
            routed_max_connections_per_source: default_routed_max_connections_per_source(),
            fallback_max_connections: default_fallback_max_connections(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Route {
    Plain(SocketAddr),
    Marked {
        upstream: SocketAddr,
        socket_marks: SocketMarks,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SocketMarks {
    pub upload: u32,
    pub download: u32,
}

impl Route {
    pub fn upstream(&self) -> SocketAddr {
        match self {
            Self::Plain(upstream) | Self::Marked { upstream, .. } => *upstream,
        }
    }

    pub fn socket_marks(&self) -> Option<SocketMarks> {
        match self {
            Self::Plain(_) => None,
            Self::Marked { socket_marks, .. } => Some(*socket_marks),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Fallbacks {
    pub unknown_sni: SocketAddr,
    pub no_sni: SocketAddr,
    pub plain_http: SocketAddr,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_hello_max")]
    pub client_hello_max_bytes: usize,
    #[serde(default = "default_hello_timeout")]
    pub client_hello_timeout_ms: u64,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_half_close_timeout")]
    pub half_close_timeout_ms: u64,
    #[serde(default = "default_fallback_lifetime_timeout")]
    pub fallback_lifetime_timeout_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            client_hello_max_bytes: default_hello_max(),
            client_hello_timeout_ms: default_hello_timeout(),
            connect_timeout_ms: default_connect_timeout(),
            half_close_timeout_ms: default_half_close_timeout(),
            fallback_lifetime_timeout_ms: default_fallback_lifetime_timeout(),
        }
    }
}

fn default_pre_parse_max_connections() -> usize {
    2_048
}

fn default_routed_max_connections() -> usize {
    36_000
}

fn default_routed_max_connections_per_source() -> usize {
    128
}

fn default_fallback_max_connections() -> usize {
    256
}

fn default_hello_max() -> usize {
    64 * 1024
}

fn default_hello_timeout() -> u64 {
    3_000
}

fn default_connect_timeout() -> u64 {
    3_000
}

fn default_half_close_timeout() -> u64 {
    10_000
}

fn default_fallback_lifetime_timeout() -> u64 {
    5_000
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read config {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid JSON config: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid config: {0}")]
    Validation(String),
}

impl Config {
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let data = fs::read(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_slice(&data)
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, ConfigError> {
        let mut config: Self = serde_json::from_slice(data)?;
        config.validate_and_normalize()?;
        Ok(config)
    }

    pub fn hello_timeout(&self) -> Duration {
        Duration::from_millis(self.limits.client_hello_timeout_ms)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.limits.connect_timeout_ms)
    }

    pub fn half_close_timeout(&self) -> Duration {
        Duration::from_millis(self.limits.half_close_timeout_ms)
    }

    pub fn fallback_lifetime_timeout(&self) -> Duration {
        Duration::from_millis(self.limits.fallback_lifetime_timeout_ms)
    }

    pub fn admitted_connection_budget(&self) -> Option<usize> {
        self.admission
            .pre_parse_max_connections
            .checked_add(self.admission.routed_max_connections)?
            .checked_add(self.admission.fallback_max_connections)
    }

    fn validate_and_normalize(&mut self) -> Result<(), ConfigError> {
        if self.allow_redirect_ingress_bind {
            ensure_redirect_ingress_bind(self.bind)?;
        } else {
            ensure_loopback("bind", self.bind)?;
        }
        ensure_loopback("health_bind", self.health_bind)?;
        if self.bind == self.health_bind {
            return Err(ConfigError::Validation(
                "bind and health_bind must be different".to_string(),
            ));
        }
        let mut normalized = HashMap::with_capacity(self.routes.len());
        for (hostname, route) in self.routes.drain() {
            let hostname = normalize_hostname(&hostname)?;
            ensure_loopback("route upstream", route.upstream())?;
            if let Some(marks) = route.socket_marks() {
                if marks.upload == 0 || marks.download == 0 || marks.upload == marks.download {
                    return Err(ConfigError::Validation(
                        "marked route requires distinct non-zero socket marks".to_string(),
                    ));
                }
            }
            if normalized.insert(hostname.clone(), route).is_some() {
                return Err(ConfigError::Validation(format!(
                    "duplicate hostname after normalization: {hostname}"
                )));
            }
        }
        self.routes = normalized;

        ensure_loopback("fallbacks.unknown_sni", self.fallbacks.unknown_sni)?;
        ensure_loopback("fallbacks.no_sni", self.fallbacks.no_sni)?;
        ensure_loopback("fallbacks.plain_http", self.fallbacks.plain_http)?;

        if self.admission.pre_parse_max_connections == 0
            || self.admission.routed_max_connections == 0
            || self.admission.routed_max_connections_per_source == 0
            || self.admission.fallback_max_connections == 0
        {
            return Err(ConfigError::Validation(
                "admission limits must be greater than zero".to_string(),
            ));
        }
        if self.admission.routed_max_connections_per_source > self.admission.routed_max_connections
        {
            return Err(ConfigError::Validation(
                "routed_max_connections_per_source must not exceed routed_max_connections"
                    .to_string(),
            ));
        }
        if self.admitted_connection_budget().is_none() {
            return Err(ConfigError::Validation(
                "admission connection budget overflow".to_string(),
            ));
        }
        if self.admitted_connection_budget().unwrap() > MAX_ADMISSION_CONNECTIONS {
            return Err(ConfigError::Validation(format!(
                "admission connection budget must not exceed {MAX_ADMISSION_CONNECTIONS}"
            )));
        }

        if !(MIN_HELLO_BYTES..=MAX_HELLO_BYTES).contains(&self.limits.client_hello_max_bytes) {
            return Err(ConfigError::Validation(format!(
                "client_hello_max_bytes must be between {MIN_HELLO_BYTES} and {MAX_HELLO_BYTES}"
            )));
        }
        if self.limits.client_hello_timeout_ms == 0
            || self.limits.connect_timeout_ms == 0
            || self.limits.half_close_timeout_ms == 0
            || self.limits.fallback_lifetime_timeout_ms == 0
        {
            return Err(ConfigError::Validation(
                "timeouts must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

fn ensure_loopback(field: &str, address: SocketAddr) -> Result<(), ConfigError> {
    if address.port() == 0 {
        return Err(ConfigError::Validation(format!(
            "{field} must use a non-zero port"
        )));
    }
    let is_loopback = match address.ip() {
        IpAddr::V4(ip) => ip.octets()[0] == Ipv4Addr::LOCALHOST.octets()[0],
        IpAddr::V6(ip) => ip.is_loopback(),
    };
    if !is_loopback {
        return Err(ConfigError::Validation(format!(
            "{field} must use a loopback IP"
        )));
    }
    Ok(())
}

fn ensure_redirect_ingress_bind(address: SocketAddr) -> Result<(), ConfigError> {
    if !address.ip().is_unspecified() || address.port() < 1024 {
        return Err(ConfigError::Validation(
            "redirect ingress bind must use a wildcard IP and unprivileged port".to_string(),
        ));
    }
    Ok(())
}

fn normalize_hostname(value: &str) -> Result<String, ConfigError> {
    let hostname = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty() || hostname.len() > 253 {
        return Err(ConfigError::Validation(format!(
            "invalid hostname: {value:?}"
        )));
    }
    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ConfigError::Validation(format!(
                "invalid exact hostname: {value:?}"
            )));
        }
    }
    Ok(hostname)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{
      "bind":"127.0.0.1:18443",
      "allow_redirect_ingress_bind":false,
      "health_bind":"127.0.0.1:19090",
      "routes":{"EXAMPLE.test.":"127.0.0.1:57270"},
      "fallbacks":{
        "unknown_sni":"127.0.0.1:4443",
        "no_sni":"127.0.0.1:4443",
        "plain_http":"127.0.0.1:8080"
      }
    }"#;

    #[test]
    fn parses_and_normalizes_a_valid_config() {
        let config = Config::from_slice(VALID.as_bytes()).unwrap();
        assert_eq!(config.routes["example.test"].upstream().port(), 57270);
        assert_eq!(config.limits.client_hello_max_bytes, 65_536);
        assert_eq!(config.admission.routed_max_connections_per_source, 128);
        assert_eq!(config.limits.half_close_timeout_ms, 10_000);
        assert_eq!(config.limits.fallback_lifetime_timeout_ms, 5_000);
        assert_eq!(config.admitted_connection_budget(), Some(38_304));
    }

    #[test]
    fn rejects_non_loopback_targets() {
        let invalid = VALID.replace("127.0.0.1:57270", "192.0.2.10:57270");
        assert!(Config::from_slice(invalid.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("loopback"));
    }

    #[test]
    fn rejects_wildcard_routes() {
        let invalid = VALID.replace("EXAMPLE.test.", "*.example.test");
        assert!(Config::from_slice(invalid.as_bytes()).is_err());
    }

    #[test]
    fn accepts_empty_routes_for_fallback_only_state() {
        let empty = VALID.replace(r#"{"EXAMPLE.test.":"127.0.0.1:57270"}"#, "{}");
        let config = Config::from_slice(empty.as_bytes()).unwrap();
        assert!(config.routes.is_empty());
    }

    #[test]
    fn accepts_a_marked_kernel_policy_route() {
        let marked = VALID.replace(
            "\"127.0.0.1:57270\"",
            "{\"upstream\":\"127.0.0.1:57270\",\"socket_marks\":{\"upload\":536871284,\"download\":536871285}}",
        );
        let config = Config::from_slice(marked.as_bytes()).unwrap();
        let route = &config.routes["example.test"];
        assert_eq!(route.upstream().port(), 57270);
        assert_eq!(route.socket_marks().unwrap().download, 536_871_285);
    }

    #[test]
    fn rejects_zero_or_identical_socket_marks() {
        for marks in [
            "{\"upload\":0,\"download\":1}",
            "{\"upload\":42,\"download\":42}",
        ] {
            let route = format!("{{\"upstream\":\"127.0.0.1:57270\",\"socket_marks\":{marks}}}");
            assert!(
                Config::from_slice(VALID.replace("\"127.0.0.1:57270\"", &route).as_bytes())
                    .is_err()
            );
        }
    }

    #[test]
    fn redirected_ingress_requires_an_explicit_narrow_opt_in() {
        let redirected = VALID.replace("127.0.0.1:18443", "0.0.0.0:18443").replace(
            "\"allow_redirect_ingress_bind\":false",
            "\"allow_redirect_ingress_bind\":true",
        );
        assert!(Config::from_slice(redirected.as_bytes()).is_ok());
        assert!(
            Config::from_slice(VALID.replace("127.0.0.1:18443", "0.0.0.0:18443").as_bytes())
                .is_err()
        );
        assert!(Config::from_slice(
            redirected
                .replace("0.0.0.0:18443", "0.0.0.0:443")
                .as_bytes()
        )
        .is_err());
    }

    #[test]
    fn rejects_a_zero_half_close_timeout() {
        let invalid = VALID.replace(
            "\n      }\n    }",
            "\n      },\n      \"limits\":{\"half_close_timeout_ms\":0}\n    }",
        );
        assert!(Config::from_slice(invalid.as_bytes()).is_err());
    }

    #[test]
    fn parses_scoped_admission_limits() {
        let configured = VALID.replace(
            "\n      \"fallbacks\":{",
            "\n      \"admission\":{\"pre_parse_max_connections\":8,\"routed_max_connections\":16,\"routed_max_connections_per_source\":4,\"fallback_max_connections\":2},\n      \"fallbacks\":{",
        );
        let config = Config::from_slice(configured.as_bytes()).unwrap();
        assert_eq!(config.admitted_connection_budget(), Some(26));
        assert_eq!(config.admission.fallback_max_connections, 2);
        assert_eq!(config.admission.routed_max_connections_per_source, 4);
    }

    #[test]
    fn rejects_zero_scoped_admission_limits() {
        let configured = VALID.replace(
            "\n      \"fallbacks\":{",
            "\n      \"admission\":{\"pre_parse_max_connections\":8,\"routed_max_connections\":16,\"routed_max_connections_per_source\":4,\"fallback_max_connections\":0},\n      \"fallbacks\":{",
        );
        assert!(Config::from_slice(configured.as_bytes()).is_err());
    }

    #[test]
    fn rejects_admission_budget_above_binary_safety_ceiling() {
        let configured = VALID.replace(
            "\n      \"fallbacks\":{",
            "\n      \"admission\":{\"pre_parse_max_connections\":60001,\"routed_max_connections\":60000,\"routed_max_connections_per_source\":128,\"fallback_max_connections\":40000},\n      \"fallbacks\":{",
        );
        assert!(Config::from_slice(configured.as_bytes()).is_err());
    }

    #[test]
    fn validates_per_source_routed_limit() {
        for limit in [0, 17] {
            let configured = VALID.replace(
                "\n      \"fallbacks\":{",
                &format!(
                    "\n      \"admission\":{{\"pre_parse_max_connections\":8,\"routed_max_connections\":16,\"routed_max_connections_per_source\":{limit},\"fallback_max_connections\":2}},\n      \"fallbacks\":{{"
                ),
            );
            assert!(Config::from_slice(configured.as_bytes()).is_err());
        }
    }
}
