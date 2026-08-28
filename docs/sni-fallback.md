# Loopback TLS fallback

`sni-fallback` is a deliberately small TLS terminator for the relay's local
fallback path. It accepts TLS on a loopback address and relays decrypted bytes
to a loopback backend. It does not implement virtual-host routing, ACME, or
public ingress policy; the exact-SNI relay remains responsible for selecting
which connections reach it.

```bash
cargo build --release --bin sni-fallback
target/release/sni-fallback \
  --listen 127.0.0.1:4443 \
  --backend 127.0.0.1:80 \
  --metrics 127.0.0.1:19091 \
  --cert /etc/sni-fallback/tls.crt \
  --key /etc/sni-fallback/tls.key \
  --allowed-sni example.com
```

All three sockets must be literal loopback addresses. Use `--check-config` to
validate the certificate/key pair without binding sockets.

At least one exact `--allowed-sni` hostname is mandatory. Repeat the option
for certificate aliases. `--allow-subdomains` additionally permits only proper
DNS-label subdomains (for example `www.example.com`, never
`notexample.com`). The gate uses rustls' incremental ClientHello parser and
drops missing or foreign SNI before certificate signing/key exchange.

The process accepts at most `--max-connections` simultaneous sessions (4096
by default). Admission is acquired before allocating a connection task.
`--handshake-timeout-ms` (5000 by default) is one deadline covering both
fragmented ClientHello collection and TLS cryptography;
`--backend-connect-timeout-ms` (1000 by default) bounds the loopback connect.
These limits prevent scanner churn and slow handshakes from growing task/FD
usage without bound.

## Certificate renewal

Write the renewed certificate and key as a pair using atomic file replacement,
then send `SIGHUP`. The process parses the complete chain and key and asks
rustls to validate that they match before a single `ArcSwap` replaces the
serving configuration. An invalid, partial, or mismatched update increments the
failure metric and leaves the previous certificate active. Connections whose
handshake already started keep their original immutable configuration.

## Shutdown

`SIGTERM` and `SIGINT` first close the listener, so no new fallback connection
is accepted. Existing TLS streams may finish for `--drain-seconds` (10 seconds
by default). Streams still active at the deadline are aborted and counted. The
systemd unit allows a longer stop timeout than the application drain deadline.

## Metrics

The loopback metrics endpoint exposes:

- `sni_fallback_certificate_reload_success_total`
- `sni_fallback_certificate_reload_failure_total`
- `sni_fallback_graceful_shutdown_total`
- `sni_fallback_forced_shutdown_connections_total`
- `sni_fallback_admission_rejected_total`
- `sni_fallback_sni_rejected_total`
- `sni_fallback_handshake_timeouts_total`
- `sni_fallback_backend_connect_timeouts_total`
- active/accepted, handshake-error, and backend-error counters

This component is not enabled by installing or building it. Production
cutover requires the staged benchmark, soak, canary and rollback checks in
[production-gates.md](production-gates.md).

## Benchmarking and runtime sizing

The standalone `sni-fallback` binary accepts `--runtime-workers N` to pin the
Tokio multithread runtime to a known number of workers during staging tests.
The default remains Tokio's available-CPU choice.  `TCP_NODELAY` is enabled on
both client and backend sockets to avoid delayed-ACK latency on the small
fallback HTTP exchanges; it does not alter TLS or HTTP semantics.

On the 12-vCPU benchmark host, a 32-client full TLS 1.2 workload showed that
four Tokio workers generally gave the best throughput/CPU balance.  An
isolated 3-second smoke run measured 797 handshakes/s at 100.6% one-core CPU,
versus 759 handshakes/s for the same binary's default runtime (results vary by
host load).  This is a staging result, not a production guarantee.  Always
repeat the longer alternating HAProxy comparison and the churn/FD gate before
cutover.
