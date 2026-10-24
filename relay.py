#!/usr/bin/env python3
"""Wizard Home Relay: a home-network exit for a Wizard's online music sources.

Some providers (YouTube) block data-center addresses. A Wizard running on a VPS can
send just those requests through this relay on a computer at home, over Tailscale.

Security model:
- SOCKS5 with a required username/password (the relay token); no anonymous use.
- Listens only on this machine's Tailscale address, never on the LAN or internet.
- Connects only to an allowlist of provider domains, by name (socks5h). Raw IP
  destinations and every other domain are refused, so it is not a general proxy.
"""
from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import os
import secrets
import socket
import subprocess
import sys
from pathlib import Path

VERSION = "0.1.0"
HOME = Path(os.environ.get("WIZARD_RELAY_HOME", Path.home() / ".config/wizard-home-relay"))
PORT = int(os.environ.get("WIZARD_RELAY_PORT", "18765"))
USER = "wizard"
# Domains YouTube Music audio and metadata need. Subdomains included.
ALLOW = (
    "youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com", "googleusercontent.com",
    "youtu.be", "youtube-nocookie.com", "googleapis.com", "google.com", "gstatic.com",
)
MAX_CONNECTIONS = 64
_active = 0


def allowed(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in ALLOW)


def token() -> str:
    path = HOME / "token"
    if not path.exists():
        HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as out:
            out.write(secrets.token_urlsafe(24))
    return path.read_text().strip()


def tailscale_ip() -> str:
    explicit = os.environ.get("WIZARD_RELAY_HOST")
    if explicit:
        return explicit
    out = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=10)
    ip = out.stdout.strip().splitlines()[0] if out.returncode == 0 and out.stdout.strip() else ""
    if not ip or not ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10"):
        sys.exit("Tailscale is not connected on this computer; the relay only listens on Tailscale.")
    return ip


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, secret: str) -> None:
    global _active
    if _active >= MAX_CONNECTIONS:
        writer.close()
        return
    _active += 1
    try:
        await asyncio.wait_for(serve(reader, writer, secret), timeout=None)
    except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError, ValueError):
        pass
    finally:
        _active -= 1
        try:
            writer.close()
        except Exception:
            pass


async def serve(reader, writer, secret) -> None:
    read = lambda n: asyncio.wait_for(reader.readexactly(n), 15)
    ver, n = await read(2)
    methods = await read(n)
    if ver != 5 or 2 not in methods:
        writer.write(b"\x05\xff")
        return
    writer.write(b"\x05\x02")
    await writer.drain()
    ver, ulen = await read(2)
    user = (await read(ulen)).decode(errors="replace")
    plen = (await read(1))[0]
    password = (await read(plen)).decode(errors="replace")
    if ver != 1 or user != USER or not hmac.compare_digest(password, secret):
        writer.write(b"\x01\x01")
        return
    writer.write(b"\x01\x00")
    await writer.drain()
    ver, cmd, _, atyp = await read(4)
    if atyp != 3:  # names only: refuse raw IPs so the allowlist can't be sidestepped
        await read({1: 4, 4: 16}.get(atyp, 0) + 2)
        writer.write(b"\x05\x02\x00\x01" + bytes(6))
        return
    host = (await read((await read(1))[0])).decode(errors="replace")
    port = int.from_bytes(await read(2), "big")
    if ver != 5 or cmd != 1 or port not in (80, 443) or not allowed(host):
        writer.write(b"\x05\x02\x00\x01" + bytes(6))
        print(f"refused {host}:{port}", flush=True)
        return
    try:
        up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, port), 15)
    except (OSError, asyncio.TimeoutError):
        writer.write(b"\x05\x04\x00\x01" + bytes(6))
        return
    writer.write(b"\x05\x00\x00\x01" + bytes(6))
    await writer.drain()
    await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer))


async def main() -> None:
    secret = token()
    host = tailscale_ip()
    server = await asyncio.start_server(lambda r, w: handle(r, w, secret), host, PORT)
    print(f"Wizard Home Relay {VERSION} on {host}:{PORT}", flush=True)
    async with server:
        await server.serve_forever()


def address() -> None:
    print(f"socks5h://{USER}:{token()}@{tailscale_ip()}:{PORT}")


if __name__ == "__main__":
    if sys.argv[1:] == ["address"]:
        address()
    elif sys.argv[1:] == ["version"]:
        print(VERSION)
    else:
        asyncio.run(main())
