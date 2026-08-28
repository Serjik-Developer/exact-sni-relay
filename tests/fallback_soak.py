#!/usr/bin/env python3
"""Repeat the bounded fallback churn gate and require stable settled RSS."""

from __future__ import annotations

import argparse
import asyncio
import ssl
import time
from pathlib import Path

from benchmark_tls_fallback import (
    HOST,
    expand_command,
    generate_certificate,
    http_backend,
    one_request,
    process_usage,
    socket_listener,
    stop_process,
    tls_context,
    wait_listening,
)
from fallback_churn import close_wait_count, disconnect, fd_count, foreign_tls, incomplete_tls


def positive(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", required=True)
    parser.add_argument("--duration", type=positive, default=3600)
    parser.add_argument("--batch", type=positive, default=256)
    parser.add_argument("--concurrency", type=positive, default=64)
    parser.add_argument("--sample-seconds", type=float, default=10.0)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--max-settled-rss-growth-mib", type=float, default=16.0)
    return parser.parse_args()


async def workload(index: int, port: int, tls: ssl.SSLContext, timeout: float) -> bool:
    kind = index % 5
    if kind in (0, 1):
        return (await one_request(port, timeout, tls))[0]
    if kind == 2:
        return await disconnect(port)
    if kind == 3:
        return await incomplete_tls(port)
    return await foreign_tls(port)


async def async_main(args: argparse.Namespace) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="fallback-soak-") as temp:
        directory = Path(temp)
        cert, key, _bundle = generate_certificate(directory)
        backend = await asyncio.start_server(http_backend, "127.0.0.1", 0)
        backend_port = int(backend.sockets[0].getsockname()[1])
        listen_port, metrics_port = socket_listener(), socket_listener()
        process = await asyncio.create_subprocess_exec(
            *expand_command(
                args.command,
                {
                    "listen_port": str(listen_port),
                    "backend_port": str(backend_port),
                    "metrics_port": str(metrics_port),
                    "cert": str(cert),
                    "key": str(key),
                    "host": HOST,
                    "config": str(directory / "unused.cfg"),
                },
            ),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await wait_listening(listen_port, process, args.timeout)
            baseline_fds = fd_count(process.pid)
            tls = tls_context()
            started = time.monotonic()
            stop_at = started + args.duration
            next_sample = started
            attempts = successes = batches = 0
            settled_rss: list[int] = []
            while time.monotonic() < stop_at:
                semaphore = asyncio.Semaphore(args.concurrency)

                async def limited(index: int) -> bool:
                    async with semaphore:
                        return await workload(index, listen_port, tls, args.timeout)

                results = await asyncio.gather(
                    *(limited(attempts + index) for index in range(args.batch))
                )
                attempts += len(results)
                successes += sum(results)
                batches += 1
                now = time.monotonic()
                if now >= next_sample:
                    await asyncio.sleep(0.2)
                    rss = process_usage(process.pid)[1]
                    settled_rss.append(rss)
                    print(
                        f"elapsed={now - started:.0f}s attempts={attempts} "
                        f"ok={successes} fds={fd_count(process.pid)} "
                        f"close_wait={close_wait_count(process.pid)} rss={rss / 1024:.1f}MiB",
                        flush=True,
                    )
                    next_sample = now + args.sample_seconds
            await asyncio.sleep(2)
            final_fds = fd_count(process.pid)
            final_close_wait = close_wait_count(process.pid)
            final_rss = process_usage(process.pid)[1]
            rss_baseline = min(settled_rss[:3] or [final_rss])
            growth_mib = (final_rss - rss_baseline) / 1024
            print(
                f"batches={batches} completed={successes}/{attempts} "
                f"fd_growth={final_fds - baseline_fds} close_wait={final_close_wait} "
                f"settled_rss_growth={growth_mib:.1f}MiB final_rss={final_rss / 1024:.1f}MiB"
            )
            return int(
                successes != attempts
                or final_fds != baseline_fds
                or final_close_wait != 0
                or growth_mib > args.max_settled_rss_growth_mib
            )
        finally:
            await stop_process(process)
            backend.close()
            await backend.wait_closed()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_main(arguments())))
