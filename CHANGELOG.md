# Changelog

## 0.1.0

- Initial standalone release.
- Exact TLS SNI routing with bounded incremental ClientHello parsing.
- Isolated admission pools, per-source routed limits, and bounded fallbacks.
- Atomic SIGHUP route reloads, Prometheus metrics, and optional socket marks.
- Adaptive full-duplex relay buffers and half-close lifecycle protection.
