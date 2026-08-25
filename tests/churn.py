#!/usr/bin/env python3
"""Bounded process-level churn regression for Exact SNI Relay.

The harness runs entirely on loopback.  It deliberately mixes complete and
fragmented TLS ClientHello records with client/server FIN, half-close and RST
paths, then verifies that the router has released every session.  It is meant
to catch lifecycle regressions such as an accumulating CLOSE_WAIT population;
it is not a throughput benchmark.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fcntl
import json
import os
import resource
import signal
import socket
import struct
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ACTIVE_METRIC = "sni_router_connections_active"
ACCEPTED_METRIC = "sni_router_connections_accepted_total"
ROUTED_METRIC = "sni_router_connections_routed_total"
PARSE_ERROR_METRIC = "sni_router_parse_errors_total"
CONNECT_ERROR_METRIC = "sni_router_connect_errors_total"


def tls_client_hello(hostname: str) -> bytes:
    """Build the small, valid TLS 1.2 ClientHello used by the Rust unit tests."""
    name = hostname.encode("ascii")
    body = bytearray((3, 3))
    body.extend(b"\x07" * 32)
    body.append(0)  # session id length
    body.extend((0, 2, 0x13, 1, 1, 0))  # cipher suites and compression

    server_name = bytearray(struct.pack("!H", len(name) + 3))
    server_name.append(0)
    server_name.extend(struct.pack("!H", len(name)))
    server_name.extend(name)
    extension = struct.pack("!HH", 0, len(server_name)) + server_name
    body.extend(struct.pack("!H", len(extension)))
    body.extend(extension)

    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def invalid_tls_prefix() -> bytes:
    """TLS-shaped scanner payload that remains incomplete until peer FIN."""
    return b"\x16\x03\x01\xff\xff" + b"\x01\x00\x00\x20" + b"scanner"


def parse_prometheus(text: str) -> dict[str, float]:
    values: dict[str, float] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 2 or "{" in fields[0]:
            continue
        with contextlib.suppress(ValueError):
            values[fields[0]] = float(fields[1])
    return values


def tcp_state_count(pid: int, state: int) -> int:
    """Count a process' IPv4/IPv6 TCP sockets in a /proc TCP state."""
    socket_inodes: set[str] = set()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        with contextlib.suppress(OSError):
            target = os.readlink(fd)
            if target.startswith("socket:[") and target.endswith("]"):
                socket_inodes.add(target[8:-1])

    count = 0
    for table in (Path(f"/proc/{pid}/net/tcp"), Path(f"/proc/{pid}/net/tcp6")):
        with contextlib.suppress(OSError):
            lines = table.read_text(encoding="ascii").splitlines()[1:]
            for line in lines:
                fields = line.split()
                if len(fields) > 9 and int(fields[3], 16) == state and fields[9] in socket_inodes:
                    count += 1
    return count


@dataclass(frozen=True)
class ProcessSample:
    fds: int
    rss_kib: int
    close_wait: int


def process_sample(pid: int) -> ProcessSample:
    fds = sum(1 for _ in Path(f"/proc/{pid}/fd").iterdir())
    status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    rss_kib = 0
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            rss_kib = int(line.split()[1])
            break
    return ProcessSample(fds=fds, rss_kib=rss_kib, close_wait=tcp_state_count(pid, 0x08))


def unused_loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


async def fetch_metrics(port: int, timeout_seconds: float = 2.0) -> dict[str, float]:
    async def fetch() -> str:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            await writer.drain()
            response = await reader.read()
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        header, separator, body = response.partition(b"\r\n\r\n")
        if not separator or b" 200 " not in header.split(b"\r\n", 1)[0]:
            raise RuntimeError("router metrics endpoint did not return HTTP 200")
        return body.decode("ascii", "replace")

    return parse_prometheus(await asyncio.wait_for(fetch(), timeout_seconds))


class ChurnBackend:
    """Opaque TCP backend which rotates graceful, half-close and RST exits."""

    def __init__(self, hang_seconds: float, open_probe: bool) -> None:
        self.accepted = 0
        self.hang_seconds = hang_seconds
        self.open_probe = open_probe
        self.server: asyncio.Server | None = None

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return int(self.server.sockets[0].getsockname()[1])

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sequence = self.accepted
        self.accepted += 1
        behavior = sequence % 4
        try:
            await asyncio.wait_for(reader.read(16 * 1024), 2.0)
            if self.open_probe and sequence == 0:
                writer.write(b"opaque-backend-response")
                await writer.drain()
                second = await asyncio.wait_for(reader.readexactly(len(b"second-ping")), 3.0)
                writer.write(b"second-pong:" + second)
                await writer.drain()
                with contextlib.suppress(TimeoutError, ConnectionError, OSError):
                    await asyncio.wait_for(reader.read(), 2.0)
                return
            if self.hang_seconds > 0:
                # Production regression shape: client sends a complete hello
                # and FIN, backend observes EOF but retains its write leg well
                # beyond the router's half-close timeout.
                with contextlib.suppress(TimeoutError, ConnectionError, OSError):
                    await asyncio.wait_for(reader.read(), 2.0)
                await asyncio.sleep(self.hang_seconds)
            elif behavior == 0:
                # Server initiates a reset while routed bytes may still arrive.
                raw = writer.get_extra_info("socket")
                if raw is not None:
                    raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                writer.transport.abort()
                return

            writer.write(b"opaque-backend-response")
            await writer.drain()
            if behavior == 1:
                # A true server half-close: FIN on the write leg while the read
                # leg drains the client's FIN through the router.
                raw = writer.get_extra_info("socket")
                if raw is not None:
                    with contextlib.suppress(OSError):
                        raw.shutdown(socket.SHUT_WR)
                with contextlib.suppress(TimeoutError, ConnectionError, OSError):
                    await asyncio.wait_for(reader.read(), 2.0)
            elif behavior == 2:
                with contextlib.suppress(TimeoutError, ConnectionError, OSError):
                    await asyncio.wait_for(reader.read(), 2.0)
        except (ConnectionError, OSError, TimeoutError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def prove_fully_open_survives_half_close_timeout(
    router_port: int,
    health_port: int,
    hello: bytes,
    half_close_timeout_ms: int,
) -> None:
    """A fully open, bidirectionally active session must have no lifecycle deadline."""
    reader, writer = await asyncio.open_connection("127.0.0.1", router_port)
    try:
        writer.write(hello + b"first-ping")
        await writer.drain()
        response = await asyncio.wait_for(reader.readexactly(len(b"opaque-backend-response")), 2.0)
        if response != b"opaque-backend-response":
            raise AssertionError(f"unexpected healthy-session response: {response!r}")

        await asyncio.sleep(max(half_close_timeout_ms / 1000 * 2, 0.1))
        metrics = await fetch_metrics(health_port)
        if metrics.get(ACTIVE_METRIC) != 1:
            raise AssertionError(
                "fully open connection did not survive the half-close timeout; "
                f"active={metrics.get(ACTIVE_METRIC)}"
            )
        writer.write(b"second-ping")
        await writer.drain()
        second = await asyncio.wait_for(
            reader.readexactly(len(b"second-pong:second-ping")),
            2.0,
        )
        if second != b"second-pong:second-ping":
            raise AssertionError(f"healthy session stopped forwarding: {second!r}")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    await wait_for_active_zero(health_port, max(2.0, half_close_timeout_ms / 1000 * 4))


def abort_writer(writer: asyncio.StreamWriter) -> None:
    raw = writer.get_extra_info("socket")
    if raw is not None:
        with contextlib.suppress(OSError):
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    writer.transport.abort()


async def churn_client(router_port: int, hello: bytes, sequence: int) -> str:
    reader, writer = await asyncio.open_connection("127.0.0.1", router_port)
    mode = sequence % 5
    try:
        if mode == 4:
            # RST while ClientHello parsing is still incomplete.
            writer.write(hello[:9])
            await writer.drain()
            abort_writer(writer)
            return "early-rst"

        # Fragment every complete ClientHello at different parser boundaries.
        split = 9 if mode in (0, 3) else max(1, len(hello) // 2)
        writer.write(hello[:split])
        await writer.drain()
        await asyncio.sleep(0)
        writer.write(hello[split:] + b"short-lived-payload")
        await writer.drain()

        if mode == 3:
            abort_writer(writer)
            return "post-hello-rst"

        # Client half-close.  The backend may answer, half-close or reset.
        writer.write_eof()
        with contextlib.suppress(ConnectionError, OSError):
            await reader.read()
        return "half-close"
    except (ConnectionError, OSError):
        return "peer-reset"
    finally:
        if not writer.is_closing():
            writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def scanner_client(
    router_port: int,
    hello: bytes,
    sequence: int,
    read_hold_seconds: float,
) -> str:
    """Public-scanner shape: FIN write leg but retain the read leg."""
    reader, writer = await asyncio.open_connection("127.0.0.1", router_port)
    try:
        if sequence % 4 == 0:
            writer.write(invalid_tls_prefix())
            outcome = "invalid-tls-fin"
        else:
            split = 9 if sequence % 2 else len(hello) // 2
            writer.write(hello[:split])
            await writer.drain()
            await asyncio.sleep(0)
            writer.write(hello[split:] + b"scanner-payload")
            outcome = "valid-sni-fin"
        await writer.drain()
        try:
            writer.write_eof()
        except OSError:
            return "peer-closed-before-fin"
        # Do not read: retain the client read leg like a scanner waiting for a
        # TLS response that the opaque backend/fallback never sends.
        await asyncio.sleep(read_hold_seconds)
        return outcome
    finally:
        del reader
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def wait_for_router(
    health_port: int,
    process: asyncio.subprocess.Process,
) -> dict[str, float]:
    deadline = time.monotonic() + 10.0
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.returncode is not None:
            raise RuntimeError(f"router exited during startup with status {process.returncode}")
        try:
            metrics = await fetch_metrics(health_port)
            if ACTIVE_METRIC in metrics:
                return metrics
        except (ConnectionError, OSError, RuntimeError, TimeoutError) as error:
            last_error = error
        await asyncio.sleep(0.05)
    raise RuntimeError(f"router did not become ready: {last_error}")


async def wait_for_active_zero(
    health_port: int,
    timeout_seconds: float,
) -> dict[str, float]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, float] = {}
    while time.monotonic() < deadline:
        last = await fetch_metrics(health_port)
        if last.get(ACTIVE_METRIC) == 0:
            # Require a second zero sample so a concurrent decrement/fetch race
            # cannot make the lifecycle assertion accidentally optimistic.
            await asyncio.sleep(0.1)
            last = await fetch_metrics(health_port)
            if last.get(ACTIVE_METRIC) == 0:
                return last
        await asyncio.sleep(0.05)
    raise AssertionError(f"active sessions did not drain to zero; last metrics={last}")


async def sample_during_wave(
    health_port: int,
    pid: int,
    task: asyncio.Task[tuple[dict[str, int], int]],
    interval_seconds: float,
) -> ProcessSample:
    peak = process_sample(pid)
    started = time.monotonic()
    while not task.done():
        metrics = await fetch_metrics(health_port)
        sample = process_sample(pid)
        peak = ProcessSample(
            fds=max(peak.fds, sample.fds),
            rss_kib=max(peak.rss_kib, sample.rss_kib),
            close_wait=max(peak.close_wait, sample.close_wait),
        )
        print(
            f"inflight_elapsed={time.monotonic() - started:.1f}s "
            f"active={int(metrics.get(ACTIVE_METRIC, -1))} fds={sample.fds} "
            f"close_wait={sample.close_wait} rss_kib={sample.rss_kib}"
        )
        try:
            await asyncio.wait_for(asyncio.shield(task), interval_seconds)
        except TimeoutError:
            pass
    return peak


async def run_wave(
    router_port: int,
    hello: bytes,
    connections: int,
    concurrency: int,
    client_timeout: float,
    scanner_mode: bool = False,
    scanner_read_hold_seconds: float = 0.0,
) -> tuple[dict[str, int], int]:
    semaphore = asyncio.Semaphore(concurrency)
    outcomes: dict[str, int] = {}
    timed_out = 0

    async def one(sequence: int) -> None:
        nonlocal timed_out
        async with semaphore:
            try:
                if scanner_mode:
                    outcome = await asyncio.wait_for(
                        scanner_client(
                            router_port,
                            hello,
                            sequence,
                            scanner_read_hold_seconds,
                        ),
                        client_timeout,
                    )
                else:
                    outcome = await asyncio.wait_for(
                        churn_client(router_port, hello, sequence),
                        client_timeout,
                    )
            except TimeoutError:
                timed_out += 1
                return
            outcomes[outcome] = outcomes.get(outcome, 0) + 1

    await asyncio.gather(*(one(sequence) for sequence in range(connections)))
    return outcomes, timed_out


async def terminate_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        await asyncio.wait_for(process.wait(), 12.0)
    except TimeoutError:
        process.kill()
        await process.wait()


async def run(args: argparse.Namespace) -> None:
    router_bin = Path(args.router_bin).resolve()
    if not router_bin.is_file() or not os.access(router_bin, os.X_OK):
        raise ValueError(f"router binary is not executable: {router_bin}")
    requested_nofile = max(4096, args.connections * 2, args.concurrency * 16)
    soft_nofile, hard_nofile = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard_nofile != resource.RLIM_INFINITY:
        requested_nofile = min(requested_nofile, hard_nofile)
    if soft_nofile < requested_nofile:
        resource.setrlimit(resource.RLIMIT_NOFILE, (requested_nofile, hard_nofile))

    backend = ChurnBackend(args.hanging_backend_seconds, args.prove_open_connection)
    backend_port = await backend.start()
    router_port = unused_loopback_port()
    health_port = unused_loopback_port()
    hello = tls_client_hello(args.hostname)
    process_max_connections = min(
        75_000,
        max(args.connections + 64, args.concurrency * 4),
    )
    # The router now reserves independent capacity for ClientHello parsing,
    # exact-SNI routes and fallbacks. Keep this lifecycle harness focused on
    # the routed path while ensuring the scoped sum fits below the process
    # ceiling selected for the test wave.
    pre_parse_connections = max(16, min(args.concurrency, process_max_connections // 4))
    fallback_connections = max(8, min(64, process_max_connections // 16))
    routed_connections = (
        process_max_connections - pre_parse_connections - fallback_connections
    )
    temp_context = tempfile.TemporaryDirectory(prefix="exact-sni-relay-churn.")
    temp_dir = Path(temp_context.name)
    config_path = temp_dir / "router.json"
    stderr_path = temp_dir / "router.stderr"
    config_path.write_text(
        json.dumps(
            {
                "bind": f"127.0.0.1:{router_port}",
                "health_bind": f"127.0.0.1:{health_port}",
                "routes": {args.hostname: f"127.0.0.1:{backend_port}"},
                "fallbacks": {
                    "unknown_sni": f"127.0.0.1:{backend_port}",
                    "no_sni": f"127.0.0.1:{backend_port}",
                    "plain_http": f"127.0.0.1:{backend_port}",
                },
                "admission": {
                    "pre_parse_max_connections": pre_parse_connections,
                    "routed_max_connections": routed_connections,
                    "fallback_max_connections": fallback_connections,
                },
                "limits": {
                    "client_hello_max_bytes": 65536,
                    "client_hello_timeout_ms": 1000,
                    "connect_timeout_ms": 1000,
                    "half_close_timeout_ms": args.half_close_timeout_ms,
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    stderr_file = stderr_path.open("wb")
    process = await asyncio.create_subprocess_exec(
        str(router_bin),
        "--config",
        str(config_path),
        "--max-connections",
        # Keep the router's admission ceiling above an entire wave. A broken
        # lifecycle must remain observable as retained active sessions, not be
        # obscured by the intentional overload/reject behavior of that ceiling.
        str(process_max_connections),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=stderr_file,
        preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (131072, 131072)),
    )
    failure: BaseException | None = None
    try:
        initial_metrics = await wait_for_router(health_port, process)
        baseline = process_sample(process.pid)
        if args.prove_open_connection:
            if args.hanging_backend_seconds > 0:
                raise ValueError(
                    "--prove-open-connection requires --hanging-backend-seconds 0"
                )
            await prove_fully_open_survives_half_close_timeout(
                router_port,
                health_port,
                hello,
                args.half_close_timeout_ms,
            )
            initial_metrics = await fetch_metrics(health_port)
            print("ok: fully open connection survived the half-close timeout")
        peak = baseline
        total_timeouts = 0
        all_outcomes: dict[str, int] = {}

        for round_number in range(1, args.rounds + 1):
            started = time.monotonic()
            wave_task = asyncio.create_task(
                run_wave(
                    router_port,
                    hello,
                    args.connections,
                    args.concurrency,
                    args.client_timeout,
                    args.scanner_mode,
                    args.scanner_read_hold_seconds,
                )
            )
            if args.scanner_mode:
                inflight_peak = await sample_during_wave(
                    health_port,
                    process.pid,
                    wave_task,
                    args.sample_interval_seconds,
                )
                peak = ProcessSample(
                    fds=max(peak.fds, inflight_peak.fds),
                    rss_kib=max(peak.rss_kib, inflight_peak.rss_kib),
                    close_wait=max(peak.close_wait, inflight_peak.close_wait),
                )
            outcomes, timed_out = await asyncio.wait_for(wave_task, args.wave_timeout)
            total_timeouts += timed_out
            for outcome, count in outcomes.items():
                all_outcomes[outcome] = all_outcomes.get(outcome, 0) + count

            metrics = await wait_for_active_zero(health_port, args.drain_timeout)
            sample = process_sample(process.pid)
            peak = ProcessSample(
                fds=max(peak.fds, sample.fds),
                rss_kib=max(peak.rss_kib, sample.rss_kib),
                close_wait=max(peak.close_wait, sample.close_wait),
            )
            print(
                f"round={round_number}/{args.rounds} elapsed={time.monotonic() - started:.2f}s "
                f"accepted={int(metrics.get(ACCEPTED_METRIC, -1))} "
                f"active={int(metrics.get(ACTIVE_METRIC, -1))} "
                f"fds={sample.fds} close_wait={sample.close_wait} rss_kib={sample.rss_kib}"
            )

        final_metrics = await wait_for_active_zero(health_port, args.drain_timeout)
        final = process_sample(process.pid)
        expected_connections = args.connections * args.rounds
        accepted_delta = int(
            final_metrics.get(ACCEPTED_METRIC, 0) - initial_metrics.get(ACCEPTED_METRIC, 0)
        )
        routed_delta = int(
            final_metrics.get(ROUTED_METRIC, 0) - initial_metrics.get(ROUTED_METRIC, 0)
        )
        parse_delta = int(
            final_metrics.get(PARSE_ERROR_METRIC, 0) - initial_metrics.get(PARSE_ERROR_METRIC, 0)
        )
        connect_error_delta = int(
            final_metrics.get(CONNECT_ERROR_METRIC, 0)
            - initial_metrics.get(CONNECT_ERROR_METRIC, 0)
        )

        errors: list[str] = []
        if accepted_delta != expected_connections:
            errors.append(f"accepted delta {accepted_delta} != attempted {expected_connections}")
        if routed_delta < expected_connections // 2:
            errors.append(
                f"only {routed_delta}/{expected_connections} connections reached exact routing"
            )
        if total_timeouts > args.max_client_timeouts:
            errors.append(f"client timeouts {total_timeouts} > allowed {args.max_client_timeouts}")
        if final_metrics.get(ACTIVE_METRIC) != 0:
            errors.append(f"active gauge is {final_metrics.get(ACTIVE_METRIC)}, expected zero")
        if final.close_wait > baseline.close_wait + args.close_wait_growth:
            errors.append(
                f"CLOSE_WAIT grew from {baseline.close_wait} to {final.close_wait} "
                f"(allowed +{args.close_wait_growth})"
            )
        if final.fds > baseline.fds + args.fd_growth:
            errors.append(
                f"FDs grew from {baseline.fds} to {final.fds} (allowed +{args.fd_growth})"
            )
        if final.rss_kib > baseline.rss_kib + args.rss_growth_kib:
            errors.append(
                f"RSS grew from {baseline.rss_kib} to {final.rss_kib} KiB "
                f"(allowed +{args.rss_growth_kib} KiB)"
            )
        # A client RST immediately after a complete ClientHello races the
        # asynchronous upstream connect. Those aggregate connect errors are
        # expected in the adversarial fixture; lifecycle release is the
        # assertion. Keep the value in the summary for diagnosis.

        summary = (
            f"attempted={expected_connections} accepted={accepted_delta} routed={routed_delta} "
            f"parse_errors={parse_delta} connect_errors={connect_error_delta} "
            f"client_timeouts={total_timeouts} outcomes={all_outcomes} "
            f"baseline={baseline} peak_after_waves={peak} final={final}"
        )
        if errors:
            raise AssertionError("; ".join(errors) + "\n" + summary)
        print("PASS: bounded TLS churn drained all router sessions")
        print(summary)
    except BaseException as error:
        failure = error
        raise
    finally:
        await terminate_process(process)
        await backend.close()
        stderr_file.close()
        if process.returncode not in (0, None) and failure is None:
            raise RuntimeError(f"router exited with status {process.returncode}")
        if failure is not None and stderr_path.exists():
            stderr_tail = stderr_path.read_text(encoding="utf-8", errors="replace")[-4000:]
            if stderr_tail:
                print("router stderr tail:\n" + stderr_tail, file=sys.stderr)
        if args.keep_temp:
            print(f"kept test artifacts in {temp_dir}")
            temp_context.cleanup = lambda: None  # type: ignore[method-assign]
        else:
            temp_context.cleanup()


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--router-bin", required=True, help="path to exact-sni-relay")
    parser.add_argument("--hostname", default="churn.test")
    parser.add_argument(
        "--connections", type=positive_int, default=2000, help="connections per wave"
    )
    parser.add_argument("--rounds", type=positive_int, default=3)
    parser.add_argument("--concurrency", type=positive_int, default=128)
    parser.add_argument("--client-timeout", type=float, default=5.0)
    parser.add_argument("--wave-timeout", type=float, default=60.0)
    parser.add_argument("--drain-timeout", type=float, default=10.0)
    parser.add_argument("--max-client-timeouts", type=int, default=0)
    parser.add_argument("--close-wait-growth", type=int, default=0)
    parser.add_argument("--fd-growth", type=int, default=8)
    parser.add_argument("--rss-growth-kib", type=int, default=32768)
    parser.add_argument(
        "--half-close-timeout-ms",
        type=positive_int,
        default=250,
        help="router half-close deadline placed in the generated config",
    )
    parser.add_argument(
        "--hanging-backend-seconds",
        type=float,
        default=2.0,
        help="hold backend write legs open after reading EOF (0 uses mixed exits)",
    )
    parser.add_argument(
        "--prove-open-connection",
        action="store_true",
        help="prove a fully open session remains active beyond the half-close timeout",
    )
    parser.add_argument(
        "--scanner-mode",
        action="store_true",
        help="mix valid SNI and incomplete TLS, client FIN and retained read legs",
    )
    parser.add_argument(
        "--scanner-read-hold-seconds",
        type=float,
        default=12.0,
        help="how long scanner clients retain their read leg after FIN",
    )
    parser.add_argument("--sample-interval-seconds", type=float, default=1.0)
    parser.add_argument("--keep-temp", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        # Port allocation is necessarily bind(0)/close/config/bind because the
        # router config needs concrete listener ports. Serialize this local
        # harness to remove cross-run TOCTOU collisions.
        with Path("/tmp/exact-sni-relay-churn.lock").open("w") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            asyncio.run(run(parse_args()))
    except (AssertionError, RuntimeError, ValueError, TimeoutError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from error
