# TLS fallback production gates

The new TLS fallback is a development candidate. Building it does not enable
it, and it must not own a production listener until every gate below passes on
the target node profile.

## Correctness

- TLS 1.2 and TLS 1.3 camouflage requests return the expected certificate and
  content over HTTP/1.1; HTTP/2 is tested when the selected candidate exposes
  an HTTP-aware mode.
- A local Xray VLESS/Reality server using the fallback as `target` passes a
  bidirectional payload test with the exact generated client settings.
- Fragmented and multi-record ClientHello, malformed TLS, no-SNI, foreign SNI,
  slow handshake, backend failure, reset, FIN and half-close cases are covered.
- Certificate reload is atomic: a valid pair is visible without restart; an
  invalid or mismatched pair increments a failure metric and leaves the old
  certificate serving.

## Resource and stability

- Run at least five alternating HAProxy/candidate rounds with the same full
  handshake workload, certificate, backend, concurrency and CPU affinity.
- Require 100% correctness, stable RSS and zero FD/CLOSE_WAIT growth after at
  least 10,000 mixed churn connections.
- Candidate CPU per successful handshake must be lower than HAProxy. Raw
  handshake throughput must be no worse than the expected production arrival
  rate with at least 100% headroom; a higher absolute benchmark score is
  preferred but is not accepted as a substitute for correctness.
- Complete a minimum 60-minute loopback soak with periodic valid HTTPS and
  Reality probes plus scanner-shaped malformed traffic. No unbounded metric,
  task, socket, FD or RSS growth is allowed.

## Canary and rollback

1. Start the candidate only on an unused loopback port and validate health,
   certificate, site response, reload and Reality probes.
2. Keep HAProxy running and warm on its existing listener. Do not remove its
   configuration or certificate.
3. Redirect only the dedicated fallback socket to the candidate; customer SNI
   routing and DNAT remain unchanged.
4. Monitor handshake success/error ratio, active sessions, CPU, RSS, FD count,
   backend failures and external Reality probes through a soak window.
5. Roll back by restoring the single fallback redirect/listener target. Verify
   the command and the public probe before canary traffic is admitted.

Any failed gate means the candidate stays out of production. Never automate a
failover from the exact-SNI relay to HAProxy solely because a synthetic TLS
probe fails; alert an administrator and preserve the last known-good route.
