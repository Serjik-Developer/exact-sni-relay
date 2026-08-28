#!/usr/bin/env python3
"""Loopback benchmark for a TLS fallback replacement.

The benchmark compares two *external* TLS terminators (for example HAProxy
and a candidate Rust service) without touching production.  Both processes
are started against an ephemeral local HTTP backend and a temporary
self-signed certificate.  The load generator opens fresh TLS connections,
performs a GET, and records successful handshakes, failures and latency.  CPU
and RSS are sampled for the complete process tree, which also accounts for a
HAProxy master/worker pair.

Commands are supplied as shell-like argument strings and are never executed
through a shell.  The following placeholders are expanded in every token:

``{listen_port}`` ``{backend_port}`` ``{metrics_port}`` ``{cert}`` ``{key}`` ``{config}``
``{host}``.

Example (HAProxy):

    python3 tests/benchmark_tls_fallback.py \
      --baseline-cmd 'haproxy -db -f {config}' \
      --candidate-cmd '/tmp/fallback --listen 127.0.0.1:{listen_port} \
                       --backend 127.0.0.1:{backend_port} --cert {cert} --key {key}'

The generated HAProxy config is suitable for a local correctness/CPU test;
operators may instead pass a command using their own generated config.  The
script deliberately uses TLS 1.2 with session tickets disabled so a new
connection represents a full certificate handshake rather than resumption.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import math
import os
import random
import shlex
import signal
import ssl
import statistics
import subprocess
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


HOST = "fallback-bench.invalid"
BODY = b"port-rental-fallback-benchmark-ok\n"
RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: " + str(len(BODY)).encode("ascii") + b"\r\n"
    b"Connection: close\r\n\r\n" + BODY
)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-cmd", required=True, help="baseline process command")
    parser.add_argument("--candidate-cmd", required=True, help="candidate process command")
    parser.add_argument("--rounds", type=positive_int, default=3)
    parser.add_argument("--workers", type=positive_int, default=32)
    parser.add_argument("--duration", type=positive_float, default=10.0)
    parser.add_argument("--timeout", type=positive_float, default=5.0)
    parser.add_argument("--warmup", type=positive_float, default=1.0)
    parser.add_argument(
        "--cpu-affinity",
        help="optional Linux CPU list applied to both servers, for example 0-3",
    )
    parser.add_argument(
        "--latency-samples",
        type=positive_int,
        default=200_000,
        help="maximum latencies retained for percentile calculation",
    )
    parser.add_argument("--json", action="store_true", help="emit one JSON document")
    return parser.parse_args()


async def http_backend(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Tiny deterministic HTTP backend; no traffic leaves loopback."""
    try:
        await asyncio.wait_for(reader.read(16 * 1024), timeout=3.0)
        writer.write(RESPONSE)
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def generate_certificate(directory: Path) -> tuple[Path, Path, Path]:
    cert = directory / "server.crt"
    key = directory / "server.key"
    bundle = directory / "server.pem"
    command = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        f"/CN={HOST}",
        "-addext",
        f"subjectAltName=DNS:{HOST}",
        "-keyout",
        str(key),
        "-out",
        str(cert),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"openssl certificate generation failed: {result.stderr}")
    bundle.write_bytes(cert.read_bytes() + key.read_bytes())
    return cert, key, bundle


def haproxy_config(path: Path, listen_port: int, backend_port: int, bundle: Path) -> None:
    # This is intentionally a minimal local fixture, not a production config.
    path.write_text(
        "\n".join(
            [
                "global",
                "  maxconn 100000",
                "  stats socket /tmp/fallback-bench-haproxy.sock mode 600 level admin",
                "defaults",
                "  mode http",
                "  option httplog",
                "  timeout connect 2s",
                "  timeout client 10s",
                "  timeout server 10s",
                "frontend tls",
                f"  bind 127.0.0.1:{listen_port} ssl crt {bundle}",
                "  default_backend local",
                "backend local",
                f"  server backend 127.0.0.1:{backend_port} check",
                "",
            ]
        ),
        encoding="utf-8",
    )


def expand_command(template: str, values: dict[str, str]) -> list[str]:
    tokens = shlex.split(template)
    if not tokens:
        raise ValueError("command is empty")
    return [token.format_map(values) for token in tokens]


def proc_stat(pid: int) -> tuple[int, int, int] | None:
    """Return (ppid, user_ticks, system_ticks) for a process."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        end = raw.rfind(")")
        fields = raw[end + 2 :].split()  # state is fields[0]
        return int(fields[1]), int(fields[11]), int(fields[12])
    except (OSError, ValueError, IndexError):
        return None


def tree_pids(root: int) -> set[int]:
    pids = {root}
    changed = True
    while changed:
        changed = False
        try:
            candidates = (int(item.name) for item in Path("/proc").iterdir() if item.name.isdigit())
        except OSError:
            candidates = ()
        for pid in candidates:
            if pid in pids:
                continue
            stat = proc_stat(pid)
            if stat is not None and stat[0] in pids:
                pids.add(pid)
                changed = True
    return pids


def process_usage(root: int) -> tuple[float, int]:
    ticks = 0
    rss_pages = 0
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, OSError, ValueError):
        page_size = 4096
    for pid in tree_pids(root):
        stat = proc_stat(pid)
        if stat is not None:
            ticks += stat[1] + stat[2]
        try:
            status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
            for line in status.splitlines():
                if line.startswith("VmRSS:"):
                    rss_pages += int(line.split()[1]) * 1024 // page_size
                    break
        except (OSError, ValueError, IndexError):
            pass
    hz = int(os.sysconf("SC_CLK_TCK"))
    return ticks / hz, rss_pages * page_size // 1024


async def wait_listening(port: int, process: asyncio.subprocess.Process, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.returncode is not None:
            stderr = b""
            if process.stderr is not None:
                with contextlib.suppress(asyncio.TimeoutError):
                    stderr = await asyncio.wait_for(process.stderr.read(32 * 1024), 0.1)
            raise RuntimeError(f"process exited {process.returncode}: {stderr.decode(errors='replace')}")
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 0.1)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.02)
    raise TimeoutError(f"process did not listen on 127.0.0.1:{port}")


def tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    if hasattr(ssl, "OP_NO_TICKET"):
        context.options |= ssl.OP_NO_TICKET
    return context


@dataclass
class LoadResult:
    attempts: int
    successes: int
    failures: int
    elapsed_seconds: float
    handshakes_per_second: float
    success_rate: float
    latency_p50_ms: float | None
    latency_p95_ms: float | None
    cpu_seconds: float
    cpu_percent_one_core: float
    max_rss_kib: int
    error_examples: list[str]


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    values.sort()
    index = min(len(values) - 1, max(0, math.ceil(fraction * len(values)) - 1))
    return values[index]


async def one_request(port: int, timeout: float, context: ssl.SSLContext) -> tuple[bool, float, str | None]:
    started = time.perf_counter()
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port, ssl=context, server_hostname=HOST),
            timeout,
        )
        writer.write(f"GET /health HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
        await asyncio.wait_for(writer.drain(), timeout)
        response = await asyncio.wait_for(reader.read(64 * 1024), timeout)
        if b"200 OK" not in response or BODY not in response:
            return False, (time.perf_counter() - started) * 1000, "incorrect HTTP response"
        return True, (time.perf_counter() - started) * 1000, None
    except Exception as error:  # bounded, aggregated below; do not log per connection
        return False, (time.perf_counter() - started) * 1000, type(error).__name__
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def run_load(
    port: int,
    workers: int,
    duration: float,
    timeout: float,
    sample_limit: int,
    pid: int,
) -> LoadResult:
    # Context is shared by clients, but OP_NO_TICKET and TLS 1.2 avoid reuse.
    context = tls_context()
    attempts = successes = 0
    latencies: list[float] = []
    errors: dict[str, int] = {}
    started = time.perf_counter()
    cpu_before, rss_before = process_usage(pid)
    max_rss = rss_before
    stop_at = started + duration
    lock = asyncio.Lock()
    sampling_done = asyncio.Event()

    async def sample_resources() -> None:
        nonlocal max_rss
        while not sampling_done.is_set():
            max_rss = max(max_rss, process_usage(pid)[1])
            try:
                await asyncio.wait_for(sampling_done.wait(), timeout=0.1)
            except asyncio.TimeoutError:
                pass

    async def worker() -> None:
        nonlocal attempts, successes, max_rss
        while time.perf_counter() < stop_at:
            ok, latency, error = await one_request(port, timeout, context)
            async with lock:
                attempts += 1
                successes += int(ok)
                if len(latencies) < sample_limit:
                    latencies.append(latency)
                elif random.randrange(max(1, attempts)) < sample_limit:
                    latencies[random.randrange(sample_limit)] = latency
                if error is not None and len(errors) < 16:
                    errors[error] = errors.get(error, 0) + 1

    sampler = asyncio.create_task(sample_resources())
    try:
        await asyncio.gather(*(worker() for _ in range(workers)))
    finally:
        sampling_done.set()
        await sampler
    elapsed = time.perf_counter() - started
    cpu_after, rss_after = process_usage(pid)
    max_rss = max(max_rss, rss_after)
    cpu = max(0.0, cpu_after - cpu_before)
    return LoadResult(
        attempts=attempts,
        successes=successes,
        failures=attempts - successes,
        elapsed_seconds=elapsed,
        handshakes_per_second=successes / elapsed if elapsed else 0.0,
        success_rate=successes / attempts if attempts else 0.0,
        latency_p50_ms=percentile(latencies, 0.50),
        latency_p95_ms=percentile(latencies, 0.95),
        cpu_seconds=cpu,
        cpu_percent_one_core=100 * cpu / elapsed if elapsed else 0.0,
        max_rss_kib=max_rss,
        error_examples=[f"{name} ({count})" for name, count in sorted(errors.items(), key=lambda x: -x[1])],
    )


async def stop_process(process: asyncio.subprocess.Process) -> str:
    if process.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            process.send_signal(signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), 5.0)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await process.wait()
    stderr = b""
    if process.stderr is not None:
        stderr = await process.stderr.read(32 * 1024)
    return stderr.decode(errors="replace")


async def run_one(
    label: str,
    template: str,
    args: argparse.Namespace,
    cert: Path,
    key: Path,
    directory: Path,
) -> dict[str, object]:
    backend = await asyncio.start_server(http_backend, "127.0.0.1", 0)
    backend_port = int(backend.sockets[0].getsockname()[1])
    # Allocate a different listener for every run; no stale process can be hit.
    listen_port = socket_listener()
    metrics_port = socket_listener()
    config = directory / f"{label}.haproxy.cfg"
    haproxy_config(config, listen_port, backend_port, directory / "server.pem")
    values = {
        "listen_port": str(listen_port),
        "backend_port": str(backend_port),
        "metrics_port": str(metrics_port),
        "cert": str(cert),
        "key": str(key),
        "config": str(config),
        "host": HOST,
    }
    command = expand_command(template, values)
    launch = command
    if args.cpu_affinity:
        launch = ["taskset", "--cpu-list", args.cpu_affinity, *command]
    process = await asyncio.create_subprocess_exec(
        *launch,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        await wait_listening(listen_port, process, args.timeout)
        # Correctness gate before any load is reported.
        correct = await one_request(listen_port, args.timeout, tls_context())
        if not correct[0]:
            raise RuntimeError(f"{label} correctness check failed: {correct[2]}")
        if args.warmup:
            await asyncio.sleep(args.warmup)
        result = await run_load(
            listen_port,
            args.workers,
            args.duration,
            args.timeout,
            args.latency_samples,
            process.pid,
        )
        document = {"label": label, **asdict(result), "command": launch}
        return document
    finally:
        stderr = await stop_process(process)
        if stderr:
            # Keep diagnostics bounded and attached to the corresponding run.
            document = locals().get("document")
            if isinstance(document, dict):
                document["stderr_tail"] = stderr[-4096:]
        backend.close()
        await backend.wait_closed()


def socket_listener() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def async_main(args: argparse.Namespace) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="tls-fallback-bench-") as temporary:
        directory = Path(temporary)
        cert, key, _bundle = generate_certificate(directory)
        samples: list[dict[str, object]] = []
        order = (("baseline", args.baseline_cmd), ("candidate", args.candidate_cmd))
        for round_index in range(args.rounds):
            for label, command in order if round_index % 2 == 0 else reversed(order):
                if not args.json:
                    print(f"round {round_index + 1}/{args.rounds}: {label}", flush=True)
                result = await run_one(label, command, args, cert, key, directory)
                result["round"] = round_index + 1
                samples.append(result)
                if not args.json:
                    print(
                        f"  {result['handshakes_per_second']:.1f} handshakes/s, "
                        f"{result['success_rate'] * 100:.2f}% ok, "
                        f"p95 {result['latency_p95_ms'] or 0:.2f} ms, "
                        f"CPU {result['cpu_percent_one_core']:.1f}%",
                        flush=True,
                    )
        summaries: dict[str, dict[str, float]] = {}
        for label in ("baseline", "candidate"):
            selected = [sample for sample in samples if sample["label"] == label]
            summaries[label] = {
                key: statistics.median(float(sample[key]) for sample in selected)
                for key in ("handshakes_per_second", "success_rate", "latency_p95_ms", "cpu_percent_one_core", "max_rss_kib")
            }
        return {
            "fixture": {
                "scope": "loopback-only; temporary cert/backend; production untouched",
                "host": HOST,
                "rounds": args.rounds,
                "workers": args.workers,
                "duration_seconds": args.duration,
                "protocol": "TLS 1.2 full handshakes (tickets disabled)",
                "cpu_affinity": args.cpu_affinity,
            },
            "samples": samples,
            "median": summaries,
        }


def main() -> int:
    args = parse_args()
    try:
        document = asyncio.run(async_main(args))
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"benchmark failed: {error}", file=os.sys.stderr)
        return 2
    if args.json:
        import json

        print(json.dumps(document, sort_keys=True))
    else:
        print("median:")
        for label, summary in document["median"].items():
            print(
                f"  {label}: {summary['handshakes_per_second']:.1f} handshakes/s, "
                f"{summary['success_rate'] * 100:.2f}% ok, "
                f"p95 {summary['latency_p95_ms']:.2f} ms, "
                f"CPU {summary['cpu_percent_one_core']:.1f}%, "
                f"RSS {summary['max_rss_kib'] / 1024:.1f} MiB"
            )
    return 0


if __name__ == "__main__":
    main()
