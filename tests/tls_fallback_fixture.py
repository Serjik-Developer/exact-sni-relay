#!/usr/bin/env python3
"""Tiny TLS fallback fixture used to self-test benchmark_tls_fallback.py.

It is intentionally not a production server.  The process terminates on
SIGTERM, serves one deterministic HTTP response per connection, and binds
loopback only.  Running it through the benchmark proves that command
placeholder expansion, TLS correctness checks, latency accounting and process
CPU/RSS sampling work even on hosts where HAProxy is not installed.
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import ssl

BODY = b"port-rental-fallback-benchmark-ok\n"
RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
    + str(len(BODY)).encode()
    + b"\r\nConnection: close\r\n\r\n"
    + BODY
)


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await reader.read(16 * 1024)
        writer.write(RESPONSE)
        await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    server = await asyncio.start_server(handle, "127.0.0.1", args.listen, ssl=context)
    loop = asyncio.get_running_loop()
    stop_future = loop.create_future()
    for name in ("SIGTERM", "SIGINT"):
        signal_name = getattr(signal, name)
        loop.add_signal_handler(signal_name, stop_future.cancel)
    try:
        await stop_future
    except asyncio.CancelledError:
        pass
    server.close()
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
