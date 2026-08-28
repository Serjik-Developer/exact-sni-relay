# Full-handshake TLS load generator

This independent crate prevents Python client scheduling from becoming the
bottleneck in the `sni-fallback` throughput comparison. It is loopback-only
and does not contact production.

Each request creates a new TCP connection, performs a verified TLS 1.2
handshake with client resumption disabled, sends one HTTP/1.1 GET, validates
the deterministic response, and closes the connection. Concurrency is capped
at 4096 and duration at one hour.

Build and test it independently:

```bash
cargo fmt --manifest-path tests/tls_loadgen/Cargo.toml -- --check
cargo test --locked --manifest-path tests/tls_loadgen/Cargo.toml
cargo clippy --locked --manifest-path tests/tls_loadgen/Cargo.toml -- -D warnings
cargo build --release --locked --manifest-path tests/tls_loadgen/Cargo.toml
```

The runner defaults to four server CPUs, seven generator CPUs and one backend
CPU. Override these sets on a different machine:

```bash
HAPROXY_BIN=/path/to/haproxy \
  tests/tls_loadgen/run_ab.sh haproxy 64 30
tests/tls_loadgen/run_ab.sh rust4 64 30

SERVER_CPUS=0-1 LOAD_CPUS=2-6 BACKEND_CPUS=7 \
  tests/tls_loadgen/run_ab.sh rust2 64 30
```

Repeat each pair at least three times and alternate their order. The reported
CPU is server-process CPU only; generator and backend consumption are
excluded. Set `HAPROXY_THREADS` when the HAProxy server CPU set does not contain
four CPUs. If an extracted HAProxy package needs private shared libraries,
configure `LD_LIBRARY_PATH` in the caller environment.

This is a synthetic staging comparison, not a production cutover or a
substitute for the churn, Reality and soak gates.
