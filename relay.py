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
import re
import shutil
from private_store import read_private, write_private

VERSION = "0.2.0"
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
    host = host.lower().removesuffix(".")
    if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                  for label in host.split(".")):
        return False
    return any(host == d or host.endswith("." + d) for d in ALLOW)


def token() -> str:
    path = HOME / "token"
    if not path.exists():
        try:
            write_private(path, secrets.token_urlsafe(32))
        except FileExistsError:
            pass
    value = read_private(path).strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value):
        raise ValueError("Invalid relay token file")
    return value


def tailscale_ip() -> str:
    candidates = [shutil.which("tailscale"),
                  "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
                  str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Tailscale/tailscale.exe")]
    executable = next((p for p in candidates if p and Path(p).is_file()), None)
    if not executable:
        raise ValueError("Install and connect Tailscale on this computer first")
    out = subprocess.run([executable, "ip", "-4"], capture_output=True, text=True, timeout=10)
    addresses = out.stdout.strip().splitlines() if out.returncode == 0 else []
    addresses = [str(ipaddress.IPv4Address(ip)) for ip in addresses
                 if ipaddress.IPv4Address(ip) in ipaddress.ip_network("100.64.0.0/10")]
    explicit = os.environ.get("WIZARD_RELAY_HOST")
    if not addresses or (explicit is not None and explicit not in addresses):
        raise ValueError("Relay host must be this computer's connected Tailscale IPv4 address")
    return explicit or addresses[0]


async def connect_provider(host, port):
    # Resolve once, reject the entire answer if any address is non-public, then
    # connect to a numeric address: no second DNS lookup/rebinding window.
    loop = asyncio.get_running_loop()
    results = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not results or any(not ipaddress.ip_address(item[4][0]).is_global for item in results):
        raise OSError("Provider resolved to a non-public address")
    for family, kind, proto, _, address in results:
        sock = socket.socket(family, kind, proto)
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, address)
            return await asyncio.open_connection(sock=sock)
        except OSError:
            sock.close()
        except BaseException:
            sock.close()
            raise
    raise OSError("Provider unavailable")


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
    if ver != 1 or user != USER or not hmac.compare_digest(password.encode(), secret.encode()):
        writer.write(b"\x01\x01")
        return
    writer.write(b"\x01\x00")
    await writer.drain()
    ver, cmd, reserved, atyp = await read(4)
    if atyp != 3:  # names only: refuse raw IPs so the allowlist can't be sidestepped
        await read({1: 4, 4: 16}.get(atyp, 0) + 2)
        writer.write(b"\x05\x02\x00\x01" + bytes(6))
        return
    host = (await read((await read(1))[0])).decode(errors="replace")
    port = int.from_bytes(await read(2), "big")
    if ver != 5 or cmd != 1 or reserved != 0 or port not in (80, 443) or not allowed(host):
        writer.write(b"\x05\x02\x00\x01" + bytes(6))

        return
    try:
        up_r, up_w = await asyncio.wait_for(connect_provider(host, port), 15)
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


def pairing(destination) -> None:
    """Explicit secret export to a NEW private file, never stdout or argv."""
    destination = Path(destination).expanduser().absolute()
    if destination.parent != (HOME / "pairing").expanduser().absolute():
        raise ValueError("Pairing exports must be inside the relay home/pairing directory")
    host = tailscale_ip()
    write_private(destination, json.dumps({
        "schema": "wizard-home-relay-pairing-v1", "host": host, "port": PORT,
        "scheme": "socks5h", "username": USER, "password": token(),
        "provider": "youtube", "allowed_domains": list(ALLOW),
    }, indent=2) + "\n")
    print("Pairing file saved privately. Import only through a trusted secret-upload flow; never paste into chat.")


if __name__ == "__main__":
    if sys.argv[1:] == ["address"]:
        sys.exit("Credential printing removed. Use: relay.py pair NEW_PRIVATE_FILE")
    elif len(sys.argv) == 3 and sys.argv[1] == "pair":
        pairing(sys.argv[2])
    elif sys.argv[1:] == ["version"]:
        print(VERSION)
    elif not sys.argv[1:]:
        asyncio.run(main())
    else:
        sys.exit("Usage: relay.py [version | pair NEW_PRIVATE_FILE]")
