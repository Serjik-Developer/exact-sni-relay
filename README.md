# Exact SNI Relay

Exact SNI Relay is a small Linux-focused TCP relay written in Rust. It reads a
bounded TLS ClientHello, selects an exact hostname route without terminating
TLS, replays the bytes it consumed, and relays the connection to a local
upstream.

It is designed for scanner-heavy shared-port ingress and deployments where
`nftables` and `tc` own forwarding, accounting, and shaping. It is not a
general-purpose reverse proxy or a drop-in replacement for HAProxy.

## Why this exists

HAProxy is an excellent general-purpose proxy. Exact SNI Relay deliberately
solves a much smaller problem: identify an exact SNI hostname, keep TLS opaque,
and move bytes with predictable resource and overload boundaries.

For that narrow workload it offers:

- **No TLS key custody.** It never terminates or decrypts TLS and has no
  certificate store, HTTP stack, or generic ACL engine.
- **Bounded parsing.** The incremental ClientHello parser supports fragmented
  handshakes across TLS records, validates nested lengths, and enforces byte
  and time limits.
- **Workload-aware admission.** Pre-parse, exact-route, and fallback traffic
  have separate budgets. Exact routes also have a full-session source-IP cap.
- **Kernel-policy hooks.** Optional per-direction `SO_MARK` values allow an
  external `nftables`/`tc` control plane to apply DNAT, accounting, and shaping.
- **Predictable reloads.** `SIGHUP` fully validates a new JSON table and swaps
  it atomically. Invalid reloads leave the old table active; existing sessions
  retain the route snapshot they accepted with.
- **Resource-conscious relay.** Each direction starts with a 4 KiB userspace
  buffer and grows to 32 KiB only after sustained transfer. Byte telemetry is
  batched off the hottest loop.
- **Operational hardening.** Fallback lifetime limits, half-close cleanup,
  bounded metric-label cardinality, and aggregate counters avoid common scan
  and log-amplification failure modes.
- **Compact implementation.** Roughly 4,000 lines of Rust, locked dependencies,
  an MIT license, and focused parser, relay, lifecycle, and churn tests.

These are design advantages for this workload, not a universal performance
claim. HAProxy is substantially more mature and supports many features this
project intentionally does not. Benchmark your own traffic profile.

## Architecture

The safe public-ingress pattern keeps the process on an unprivileged port:

```text
Internet TCP/443
    -> nftables REDIRECT
    -> Exact SNI Relay on :18443
    -> exact SNI route to 127.0.0.1:<route-port>
    -> optional SO_MARK + nftables OUTPUT DNAT
    -> backend
```

Plain routes connect to a loopback service. Marked routes still name a
loopback address, but the socket mark lets a separately managed kernel policy
redirect that connection. The relay itself does not install firewall, NAT, or
traffic-control rules.

## Build

Requirements: Linux and Rust 1.85 or newer. The repository pins the Rust 1.85
release line, so a normal `cargo` invocation through rustup uses a compatible
compiler.

```bash
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
```

The binary is `target/release/exact-sni-relay`.

## Configuration

Start from [examples/config.json](examples/config.json):

```json
{
  "bind": "127.0.0.1:18443",
  "allow_redirect_ingress_bind": false,
  "health_bind": "127.0.0.1:19090",
  "routes": {
    "service.example.net": "127.0.0.1:15443",
    "marked.example.net": {
      "upstream": "127.0.0.1:15444",
      "socket_marks": {
        "upload": 536871284,
        "download": 536871285
      }
    }
  },
  "fallbacks": {
    "unknown_sni": "127.0.0.1:14443",
    "no_sni": "127.0.0.1:14443",
    "plain_http": "127.0.0.1:18080"
  },
  "admission": {
    "pre_parse_max_connections": 2048,
    "routed_max_connections": 12000,
    "routed_max_connections_per_source": 128,
    "fallback_max_connections": 256
  },
  "limits": {
    "client_hello_max_bytes": 65536,
    "client_hello_timeout_ms": 3000,
    "connect_timeout_ms": 3000,
    "half_close_timeout_ms": 10000,
    "fallback_lifetime_timeout_ms": 5000
  }
}
```

Validate without binding sockets:

```bash
exact-sni-relay --config /etc/exact-sni-relay/config.json --check-config
```

Run the service:

```bash
exact-sni-relay \
  --config /etc/exact-sni-relay/config.json \
  --max-connections 15000
```

`--max-connections` validates the sum of the configured admission pools and
sets the listener backlog ceiling. It is not an additional fourth admission
semaphore. Admission and bind-address changes require a restart; route-table
changes can use `SIGHUP`.

### Routing behavior

- Routes are exact, lowercase-normalized ASCII DNS hostnames.
- Wildcards and regex routes are rejected.
- IDNs must be configured in punycode form.
- Route and fallback upstreams must use loopback addresses.
- Unknown SNI, valid TLS without SNI, and supported plain HTTP methods have
  separate required fallbacks.
- Malformed TLS-shaped or unsupported plaintext input is closed and counted.
- Fallback services must be supplied and operated separately.

### Public redirected ingress

Set:

```json
"bind": "0.0.0.0:18443",
"allow_redirect_ingress_bind": true
```

and redirect public TCP/443 to that unprivileged local port with your own
firewall rules. The flag does not permit a privileged direct `:443` bind. Keep
`:18443` blocked from direct external access so it is reachable only through
the intended redirect path.

### Socket marks

Marked routes set one mark on the accepted/client leg and another on the
upstream leg. This supports directional policy and accounting without parsing
TLS twice. The included systemd example grants only `CAP_NET_RAW`, which is
sufficient for `SO_MARK` on Linux 5.17 and newer. If every route is unmarked,
remove the two capability directives from the unit.

## Health and metrics

The loopback health listener exposes:

- `GET /healthz` — process/listener responsiveness only; it does not probe
  configured backends.
- `GET /metrics` — Prometheus counters and gauges for admission, active
  sessions, routing/fallback decisions, parse/connect failures, reloads, and
  relayed bytes.

Routed and fallback connect health are separated so Internet scan failures do
not look like customer-route failures. Per-route connect-error labels retain a
maximum of 256 distinct values and collapse later routes into `__overflow__`.
Byte metrics are operational telemetry, not durable billing counters.

Expected connection failures are counted instead of logged once per socket,
which prevents attacker-controlled journald growth.

## Lifecycle regression

The loopback-only churn harness exercises fragmented ClientHello records,
FIN/RST behavior, backend half-close stalls, resource cleanup, and healthy
long-lived sessions:

```bash
python3 tests/churn.py \
  --router-bin target/release/exact-sni-relay \
  --connections 2000 --rounds 3 --concurrency 128
```

This is a lifecycle regression, not a throughput benchmark.

### TLS fallback benchmark

The fallback is the one path where a TLS terminator (currently HAProxy in
production) may still be needed.  Before replacing it, compare a candidate
locally with the supplied benchmark.  It generates a temporary self-signed
certificate and loopback HTTP backend, so it never contacts production:

```bash
python3 tests/benchmark_tls_fallback.py \
  --baseline-cmd 'haproxy -db -f {config}' \
  --candidate-cmd 'my-fallback --listen 127.0.0.1:{listen_port} \
    --backend 127.0.0.1:{backend_port} --cert {cert} --key {key}' \
  --workers 64 --duration 30 --rounds 5 --json
```

Commands are split with `shlex` (no shell is invoked).  `{listen_port}`,
`{backend_port}`, `{metrics_port}`, `{cert}`, `{key}`, `{config}`, and `{host}`
are expanded per run. The report includes successful full TLS 1.2 handshakes
per second, success rate, p50/p95 latency, process-tree CPU and peak RSS. A correctness
request must return the deterministic `200 OK` fixture before load starts;
failed requests are aggregated with bounded error examples.  For hosts
without HAProxy, the fixture below can validate the harness itself:

```bash
python3 tests/benchmark_tls_fallback.py \
  --baseline-cmd 'python3 tests/tls_fallback_fixture.py --listen {listen_port} --cert {cert} --key {key}' \
  --candidate-cmd 'python3 tests/tls_fallback_fixture.py --listen {listen_port} --cert {cert} --key {key}'
```

This is a benchmark and correctness gate, not a production cutover.  Treat a
candidate as ready only after it matches the fallback's required certificate,
SNI, HTTP behavior, overload limits, and long-lived connection semantics on a
staging host.

Standalone fallback regression gates are also loopback-only:

```bash
python3 tests/fallback_churn.py \
  --command 'target/release/sni-fallback \
    --listen 127.0.0.1:{listen_port} \
    --backend 127.0.0.1:{backend_port} \
    --metrics 127.0.0.1:{metrics_port} \
    --cert {cert} --key {key} --allowed-sni {host} \
    --runtime-workers 4'

python3 tests/reality_xray_smoke.py \
  --candidate target/release/sni-fallback --xray /path/to/xray --json

python3 tests/fallback_soak.py --duration 3600 \
  --command 'target/release/sni-fallback \
    --listen 127.0.0.1:{listen_port} \
    --backend 127.0.0.1:{backend_port} \
    --metrics 127.0.0.1:{metrics_port} \
    --cert {cert} --key {key} --allowed-sni {host} \
    --runtime-workers 4'
```

The churn gate mixes valid HTTPS, disconnects, incomplete TLS and foreign-SNI
traffic and checks FD/RSS/CLOSE_WAIT cleanup. The Reality gate proves both the
camouflage response and a bidirectional VLESS/Reality payload. The soak gate
repeats the same mixed profile for a bounded duration and fails
on request errors, FD/CLOSE_WAIT growth, or excessive settled RSS growth.

For server-saturating comparisons, the loopback-only Rust generator avoids
Python scheduling becoming the bottleneck. It performs verified full TLS 1.2
handshakes with resumption disabled and reports server-process CPU separately
from generator/backend CPU. See
[tests/tls_loadgen/README.md](tests/tls_loadgen/README.md) for reproducible
commands and [the staging result](docs/tls-fallback-benchmark-results.md) for
the current development-host methodology and measurements.

The companion TLS terminator is `sni-fallback`:

```bash
cargo build --release --locked --bin sni-fallback
target/release/sni-fallback --check-config \
  --listen 127.0.0.1:4443 --backend 127.0.0.1:80 \
  --metrics 127.0.0.1:19091 --cert /etc/sni-fallback/tls.crt \
  --key /etc/sni-fallback/tls.key --allowed-sni example.com
```

It is loopback-only, reloads a validated certificate/key pair on `SIGHUP`, and
drains existing connections on `SIGTERM`; see
[docs/sni-fallback.md](docs/sni-fallback.md). The release gate and rollback
procedure are in [docs/production-gates.md](docs/production-gates.md).

## Comparison

| Capability | Exact SNI Relay | HAProxy / general proxies | Typical small SNI routers |
| --- | --- | --- | --- |
| Primary scope | Exact-SNI TCP TLS passthrough | General L4/L7 proxying | TLS passthrough varies by project |
| TLS termination and certificates | No | Yes | Usually no |
| ClientHello parser limits | Explicit byte/time bounds | Mature configurable inspection | Varies |
| Overload isolation | Separate pre-parse/routed/fallback pools, per-source cap | Can model controls with proxy limits, tables, and timeouts | Often one global limit |
| Reload | Validated atomic route-table swap | Mature runtime API/seamless reload | Varies |
| Kernel integration | Optional directional `SO_MARK` | Marking is possible with platform/config support | Rare and project-specific |
| Observability | Prometheus with bounded route-label cardinality | Rich mature stats/tooling | Varies |
| Feature breadth | Intentionally narrow | Extensive | Narrow to moderate |
| Maturity | Young; no independent audit | Long production history and ecosystem | Varies |

Choose HAProxy when you need TLS termination, mTLS, certificate automation,
dynamic load balancing, active backend health checks, retries, rich ACLs,
PROXY protocol, HTTP processing, broad platform support, or established
operational tooling.

## Limitations

- Linux and TCP only; no UDP or QUIC.
- Routing depends on plaintext SNI. Encrypted ClientHello (ECH) hides it.
- Exact ASCII hostnames only; no wildcard, regex, ALPN, or arbitrary ACLs.
- Loopback upstreams/fallbacks only.
- No TLS termination, mTLS, ACME, certificate storage, HTTP routing, retries,
  pools, active backend health checks, or PROXY protocol.
- Does not preserve the original client address at the upstream TCP socket.
- Does not configure DNAT/SNAT, traffic shaping, quotas, or billing.
- Per-source caps can affect many legitimate clients behind one CGNAT address.
- Real capacity depends on RAM, file-descriptor limits, kernel settings,
  connection lifetime, churn, and traffic distribution.
- The hard accepted configuration ceiling is 75,000 connections.
- The project has not undergone an independent security audit.

## License

Exact SNI Relay is licensed under the [MIT License](LICENSE). Dependencies keep
their respective licenses; consult `Cargo.lock` and your preferred Rust license
audit/SBOM tooling before redistributing binaries.
