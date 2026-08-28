#!/usr/bin/env python3
"""Independent loopback TLS probe using parallel ``openssl s_client`` calls.

This helper is deliberately separate from benchmark_tls_fallback.py: it is a
correctness/stress cross-check with another TLS implementation, not a precise
server CPU benchmark.  Process startup is included in its latency and rate.
Only loopback destinations are accepted.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import math
import shutil
import statistics
import time


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=positive_int, required=True)
    parser.add_argument("--host", default="fallback-bench.invalid")
    parser.add_argument("--requests", type=positive_int, default=100)
    parser.add_argument("--concurrency", type=positive_int, default=16)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--expect", default="port-rental-fallback-benchmark-ok")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def percentile(values: list[float], fraction: float) -> float:
    values.sort()
    index = max(0, min(len(values) - 1, math.ceil(fraction * len(values)) - 1))
    return values[index]


async def request(args: argparse.Namespace, semaphore: asyncio.Semaphore) -> tuple[bool, float, str]:
    request_bytes = (
        f"GET /health HTTP/1.1\r\nHost: {args.host}\r\nConnection: close\r\n\r\n"
    ).encode()
    command = [
        "openssl",
        "s_client",
        "-connect",
        f"{args.address}:{args.port}",
        "-servername",
        args.host,
        "-tls1_2",
        "-no_ticket",
        "-quiet",
    ]
    async with semaphore:
        started = time.perf_counter()
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(request_bytes), timeout=args.timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return False, (time.perf_counter() - started) * 1000, "timeout"
    elapsed = (time.perf_counter() - started) * 1000
    expected = args.expect.encode()
    if process.returncode != 0:
        detail = stderr.decode(errors="replace").strip().splitlines()
        return False, elapsed, detail[-1][:160] if detail else f"exit {process.returncode}"
    if b"200 OK" not in stdout or expected not in stdout:
        return False, elapsed, "incorrect HTTP response"
    return True, elapsed, ""


async def async_main(args: argparse.Namespace) -> dict[str, object]:
    if shutil.which("openssl") is None:
        raise RuntimeError("openssl is required")
    try:
        address = ipaddress.ip_address(args.address)
    except ValueError as error:
        raise RuntimeError("--address must be a literal loopback IP") from error
    if not address.is_loopback:
        raise RuntimeError("only loopback destinations are allowed")
    semaphore = asyncio.Semaphore(args.concurrency)
    started = time.perf_counter()
    results = await asyncio.gather(*(request(args, semaphore) for _ in range(args.requests)))
    elapsed = time.perf_counter() - started
    successful = [latency for ok, latency, _error in results if ok]
    errors: dict[str, int] = {}
    for ok, _latency, error in results:
        if not ok:
            errors[error] = errors.get(error, 0) + 1
    return {
        "scope": "loopback-only openssl s_client cross-check",
        "requests": args.requests,
        "successes": len(successful),
        "failures": args.requests - len(successful),
        "success_rate": len(successful) / args.requests,
        "elapsed_seconds": elapsed,
        "handshakes_per_second": len(successful) / elapsed,
        "latency_p50_ms": statistics.median(successful) if successful else None,
        "latency_p95_ms": percentile(successful, 0.95) if successful else None,
        "errors": sorted(errors.items(), key=lambda item: -item[1])[:10],
    }


def main() -> int:
    args = parse_args()
    try:
        result = asyncio.run(async_main(args))
    except (OSError, RuntimeError) as error:
        print(f"probe failed: {error}")
        return 2
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            f"{result['successes']}/{result['requests']} ok, "
            f"{result['handshakes_per_second']:.1f} handshakes/s, "
            f"p95={result['latency_p95_ms'] or 0:.2f} ms"
        )
        if result["errors"]:
            print(f"errors: {result['errors']}")
    return 0 if result["failures"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
