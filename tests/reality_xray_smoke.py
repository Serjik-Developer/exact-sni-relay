#!/usr/bin/env python3
"""Loopback-only Reality/Xray compatibility test for the Rust TLS fallback.

The test starts an ephemeral HTTP camouflage backend, the candidate TLS
terminator, a Reality server whose ``target`` points at the candidate, and a
Reality client. It verifies both a normal camouflage HTTPS request and a real
VLESS/Reality request through the client's SOCKS listener.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

HOST = "fallback-reality.invalid"
BODY = b"port-rental-reality-fallback-ok\n"


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def generate_certificate(directory: Path) -> tuple[Path, Path]:
    cert = directory / "server.crt"
    key = directory / "server.key"
    result = subprocess.run(
        [
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
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"certificate generation failed: {result.stderr}")
    return cert, key


async def backend(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await asyncio.wait_for(reader.read(16 * 1024), 3)
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(BODY)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + BODY
        )
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(64 * 1024):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def wait_tcp(port: int, process: asyncio.subprocess.Process, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.returncode is not None:
            error = (await process.stderr.read()).decode(errors="replace")
            raise RuntimeError(f"process exited {process.returncode}: {error[-2000:]}")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), 0.1
            )
            del reader
            writer.close()
            await writer.wait_closed()
            return
        except (OSError, asyncio.TimeoutError):
            await asyncio.sleep(0.03)
    raise TimeoutError(f"port {port} did not become ready")


async def stop(process: asyncio.subprocess.Process | None) -> str:
    if process is None:
        return ""
    if process.returncode is None:
        process.send_signal(signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), 5)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
    return (await process.stderr.read()).decode(errors="replace") if process.stderr else ""


async def socks_echo(port: int, target_port: int, payload: bytes) -> bytes:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port), 3
    )
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await asyncio.wait_for(reader.readexactly(2), 3) != b"\x05\x00":
            raise RuntimeError("SOCKS authentication negotiation failed")
        writer.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big"))
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(4), 5)
        if reply[1] != 0:
            raise RuntimeError(f"SOCKS connect failed with status {reply[1]}")
        address_type = reply[3]
        if address_type == 1:
            await reader.readexactly(4)
        elif address_type == 3:
            await reader.readexactly((await reader.readexactly(1))[0])
        elif address_type == 4:
            await reader.readexactly(16)
        else:
            raise RuntimeError("invalid SOCKS reply address type")
        await reader.readexactly(2)
        writer.write(payload)
        await writer.drain()
        return await asyncio.wait_for(reader.readexactly(len(payload)), 15)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def x25519(xray: Path) -> tuple[str, str]:
    result = subprocess.run([str(xray), "x25519"], capture_output=True, text=True, check=True)
    values = {}
    for line in result.stdout.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            values[key] = value.strip()
    return values["PrivateKey"], values["Password (PublicKey)"]


async def async_main(args: argparse.Namespace) -> dict[str, object]:
    xray = Path(args.xray).resolve()
    candidate = Path(args.candidate).resolve()
    if not xray.is_file() or not os.access(xray, os.X_OK):
        raise RuntimeError(f"Xray executable not found: {xray}")
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise RuntimeError(f"candidate executable not found: {candidate}")

    with tempfile.TemporaryDirectory(prefix="fallback-reality-") as raw_temp:
        directory = Path(raw_temp)
        cert, key = generate_certificate(directory)
        backend_server = await asyncio.start_server(backend, "127.0.0.1", 0)
        echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
        backend_port = int(backend_server.sockets[0].getsockname()[1])
        echo_port = int(echo_server.sockets[0].getsockname()[1])
        fallback_port, reality_port, socks_port, health_port = (
            free_port(), free_port(), free_port(), free_port()
        )
        user_id = str(uuid.uuid4())
        private_key, public_key = x25519(xray)
        short_id = "0123456789abcdef"

        xray_log_level = "debug" if args.verbose else "warning"
        server_config = {
            "log": {"loglevel": xray_log_level},
            "inbounds": [{
                "listen": "127.0.0.1", "port": reality_port, "protocol": "vless",
                "settings": {"clients": [{"id": user_id, "flow": "xtls-rprx-vision"}], "decryption": "none"},
                "streamSettings": {
                    "network": "raw", "security": "reality",
                    "realitySettings": {
                        "show": False, "target": f"127.0.0.1:{fallback_port}",
                        "xver": 0, "serverNames": [HOST], "privateKey": private_key,
                        "shortIds": [short_id],
                    },
                },
            }],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        }
        client_config = {
            "log": {"loglevel": xray_log_level},
            "inbounds": [{
                "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": reality_port, "users": [{"id": user_id, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
                "streamSettings": {
                    "network": "raw", "security": "reality",
                    "realitySettings": {"fingerprint": "chrome", "serverName": HOST, "publicKey": public_key, "shortId": short_id, "spiderX": "/"},
                },
            }],
        }
        server_path, client_path = directory / "server.json", directory / "client.json"
        server_path.write_text(json.dumps(server_config), encoding="utf-8")
        client_path.write_text(json.dumps(client_config), encoding="utf-8")

        candidate_process = server_process = client_process = None
        try:
            candidate_process = await asyncio.create_subprocess_exec(
                str(candidate), "--listen", f"127.0.0.1:{fallback_port}",
                "--metrics", f"127.0.0.1:{health_port}",
                "--cert", str(cert), "--key", str(key),
                "--backend", f"127.0.0.1:{backend_port}", "--allowed-sni", HOST,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await wait_tcp(fallback_port, candidate_process)
            server_process = await asyncio.create_subprocess_exec(
                str(xray), "run", "-config", str(server_path),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            )
            await wait_tcp(reality_port, server_process)
            client_process = await asyncio.create_subprocess_exec(
                str(xray), "run", "-config", str(client_path),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            )
            await wait_tcp(socks_port, client_process)

            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls.check_hostname = False
            tls.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", fallback_port, ssl=tls, server_hostname=HOST
            )
            writer.write(f"GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
            camouflage = await asyncio.wait_for(reader.read(64 * 1024), 5)
            writer.close()
            await writer.wait_closed()
            if b"200 OK" not in camouflage or BODY not in camouflage:
                raise RuntimeError("candidate camouflage HTTP response is incorrect")

            payload = os.urandom(64 * 1024)
            try:
                echoed = await socks_echo(socks_port, echo_port, payload)
            except (OSError, RuntimeError, EOFError) as error:
                diagnostics = []
                for label, process in (
                    ("xray-client", client_process),
                    ("xray-server", server_process),
                    ("candidate", candidate_process),
                ):
                    stderr = await stop(process)
                    if process is client_process:
                        client_process = None
                    elif process is server_process:
                        server_process = None
                    else:
                        candidate_process = None
                    if stderr:
                        diagnostics.append(f"{label}: {stderr[-2000:]}")
                detail = "\n".join(diagnostics)
                suffix = f"\n{detail}" if detail else "\n(no stderr captured)"
                raise RuntimeError(f"Reality echo failed: {error}{suffix}") from error
            if echoed != payload:
                raise RuntimeError("Reality payload corruption")
            return {
                "scope": "loopback-only",
                "camouflage_https": "ok",
                "vless_reality": "ok",
                "echo_bytes": len(payload),
            }
        finally:
            errors = []
            for process in (client_process, server_process, candidate_process):
                stderr = await stop(process)
                if stderr:
                    errors.append(stderr[-2000:])
            backend_server.close()
            echo_server.close()
            await backend_server.wait_closed()
            await echo_server.wait_closed()
            if errors and args.verbose:
                print("\n".join(errors), file=os.sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--xray", default="/root/xray-test/xray")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(async_main(args))
    except (
        OSError,
        RuntimeError,
        TimeoutError,
        asyncio.IncompleteReadError,
        subprocess.SubprocessError,
    ) as error:
        detail = str(error) or type(error).__name__
        print(f"Reality smoke test failed: {detail}", file=os.sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True) if args.json else result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
