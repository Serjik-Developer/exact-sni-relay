#!/usr/bin/env python3
"""Loopback churn/FD gate for the standalone TLS fallback candidate."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import ssl
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
    tree_pids,
    wait_listening,
)


def positive(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", required=True)
    parser.add_argument("--rounds", type=positive, default=5)
    parser.add_argument("--connections", type=positive, default=2000)
    parser.add_argument("--concurrency", type=positive, default=128)
    parser.add_argument("--settle-seconds", type=float, default=2.0)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--max-fd-growth", type=int, default=8)
    return parser.parse_args()


def fd_count(root: int) -> int:
    total = 0
    for pid in tree_pids(root):
        with contextlib.suppress(OSError):
            total += sum(1 for _ in Path(f"/proc/{pid}/fd").iterdir())
    return total


def socket_inodes(root: int) -> set[str]:
    result: set[str] = set()
    for pid in tree_pids(root):
        with contextlib.suppress(OSError):
            for descriptor in Path(f"/proc/{pid}/fd").iterdir():
                with contextlib.suppress(OSError):
                    target = os.readlink(descriptor)
                    if target.startswith("socket:["):
                        result.add(target[8:-1])
    return result


def close_wait_count(root: int) -> int:
    inodes = socket_inodes(root)
    total = 0
    for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        with contextlib.suppress(OSError):
            for line in table.read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 9 and fields[3] == "08" and fields[9] in inodes:
                    total += 1
    return total


async def disconnect(port: int) -> bool:
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.close()
        await writer.wait_closed()
        return True
    except OSError:
        return False


async def incomplete_tls(port: int) -> bool:
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x16\x03\x01\xff\xff\x01\x00\x00")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return True
    except OSError:
        return False


async def foreign_tls(port: int) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                "127.0.0.1", port, ssl=context, server_hostname="foreign.invalid"
            ),
            2,
        )
        return False
    except (OSError, ssl.SSLError, asyncio.TimeoutError):
        return True
    finally:
        if writer:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def churn_one(index: int, port: int, timeout: float, tls: ssl.SSLContext) -> bool:
    kind = index % 4
    if kind == 0:
        return (await one_request(port, timeout, tls))[0]
    if kind == 1:
        return await disconnect(port)
    if kind == 2:
        return await incomplete_tls(port)
    return await foreign_tls(port)


async def async_main(args: argparse.Namespace) -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="fallback-churn-") as temp:
        directory = Path(temp)
        cert, key, _bundle = generate_certificate(directory)
        backend = await asyncio.start_server(http_backend, "127.0.0.1", 0)
        backend_port = int(backend.sockets[0].getsockname()[1])
        listen_port, metrics_port = socket_listener(), socket_listener()
        command = expand_command(
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
        )
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await wait_listening(listen_port, process, args.timeout)
            baseline_fds = fd_count(process.pid)
            baseline_rss = process_usage(process.pid)[1]
            maximum_fds, maximum_rss = baseline_fds, baseline_rss
            total_ok = 0
            tls = tls_context()
            for round_index in range(args.rounds):
                semaphore = asyncio.Semaphore(args.concurrency)

                async def limited(index: int) -> bool:
                    async with semaphore:
                        return await churn_one(index, listen_port, args.timeout, tls)

                results = await asyncio.gather(
                    *(limited(index) for index in range(args.connections))
                )
                total_ok += sum(results)
                maximum_fds = max(maximum_fds, fd_count(process.pid))
                maximum_rss = max(maximum_rss, process_usage(process.pid)[1])
                print(
                    f"round {round_index + 1}: {sum(results)}/{len(results)} completed; "
                    f"fds={fd_count(process.pid)} "
                    f"rss={process_usage(process.pid)[1] / 1024:.1f} MiB",
                    flush=True,
                )
            await asyncio.sleep(args.settle_seconds)
            final_fds = fd_count(process.pid)
            final_rss = process_usage(process.pid)[1]
            close_wait = close_wait_count(process.pid)
            expected = args.rounds * args.connections
            print(
                f"baseline_fds={baseline_fds} final_fds={final_fds} "
                f"fd_growth={final_fds - baseline_fds} max_fds={maximum_fds} "
                f"close_wait={close_wait} baseline_rss={baseline_rss / 1024:.1f}MiB "
                f"final_rss={final_rss / 1024:.1f}MiB max_rss={maximum_rss / 1024:.1f}MiB "
                f"completed={total_ok}/{expected}"
            )
            return int(
                total_ok != expected
                or final_fds - baseline_fds > args.max_fd_growth
                or close_wait != 0
            )
        finally:
            await stop_process(process)
            backend.close()
            await backend.wait_closed()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_main(arguments())))
