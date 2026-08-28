# TLS fallback staging benchmark

Date: 2026-08-27. Scope: loopback-only development host; production untouched.

Host: 12 vCPU AMD EPYC under KVM, Linux 6.12. HAProxy 3.0.11 with OpenSSL
3.5.6 was compared with the release `sni-fallback` candidate using four Tokio
runtime workers. Servers were pinned to CPUs 0-3, the Rust generator to CPUs
4-10, and the deterministic backend to CPU 11.

The workload used fresh, verified TLS 1.2 connections with resumption
disabled and one HTTP GET per connection. Each cell is the median of three
alternating six-second runs; all requests succeeded.

| Concurrency | Server | Handshakes/s | Server CPU | RSS | Handshakes/s per CPU core |
| ---: | --- | ---: | ---: | ---: | ---: |
| 32 | HAProxy | 2,904 | 386.7% | 39.5 MiB | 751 |
| 32 | Rust candidate | 3,113 | 368.9% | 8.2 MiB | 864 |
| 64 | HAProxy | 2,704 | 371.6% | 41.6 MiB | 731 |
| 64 | Rust candidate | 3,337 | 384.4% | 9.1 MiB | 889 |

In this profile the Rust candidate delivered 7.2% more throughput at
concurrency 32 and 23.4% more at concurrency 64. Successful handshakes per
CPU core improved by 15.1% and 21.6%, respectively, while RSS was about 79%
lower. These results apply only to this host and synthetic workload.

Worker scaling at concurrency 64 was nearly linear through the four CPUs:
one worker produced a 980 handshakes/s median at 101.8% CPU; two produced
1,851 handshakes/s at 202.6% CPU; measured four-worker samples produced
3.3-3.5k handshakes/s at approximately 381-387% CPU. No claim is made for
oversubscribing runtime workers beyond the allocated CPUs.

After the hot-path allocation/refcount cleanup, short six-second confirmation
runs produced 3,376 handshakes/s at concurrency 32 and 3,480 handshakes/s at
concurrency 64, with zero failures and 8.1-9.3 MiB RSS. These short samples
confirm that the cleanup did not regress the candidate; they are intentionally
not used to claim a precise improvement over the longer alternating medians.

Reproduce with [the load-generator instructions](../tests/tls_loadgen/README.md).
Run longer alternating rounds before making any production decision.

## Stability gates on the optimized binary

The optimized release binary completed the mandatory 60-minute mixed loopback
soak on 2026-08-27: 5,236,992/5,236,992 operations succeeded, FD growth was
zero, CLOSE_WAIT was zero, settled RSS growth was 1.5 MiB, and final RSS was
9.2 MiB. A separate 10,000-connection churn run also completed without FD or
CLOSE_WAIT growth. The loopback Xray test passed both camouflage HTTPS and a
65,536-byte bidirectional VLESS/Reality payload.

These are staging gates, not permission to change a production listener. The
unused-loopback canary and explicit rollback procedure remain required.
