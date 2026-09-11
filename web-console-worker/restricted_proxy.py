"""Per-session HTTP/CONNECT transport to one validated origin and pinned IP.

TLS stays end-to-end with Chromium. No request body, credential or URL logging.
Redirects can use only administrator-configured origins, each pinned to a validated IP.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hmac
import secrets
from urllib.parse import urlsplit

HEADER_LIMIT = 65536
HEADER_NAME = b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz"


class PinnedProxy:
    def __init__(self, host, port, address, enabled, scheme="https", resolve=None):
        self.host, self.port, self.address = host, port, address
        self.enabled = enabled
        self.scheme = scheme
        self.resolve = resolve
        self.blocked_destination = False
        self.username, self.password = secrets.token_hex(16), secrets.token_hex(24)
        self.authorization = b"Basic " + base64.b64encode(f"{self.username}:{self.password}".encode())
        self.listener = None
        self.tasks = set()
        self.writers = set()
        self.closed = False

    async def start(self):
        self.listener = await asyncio.start_server(self.accept, "127.0.0.1", 0, limit=HEADER_LIMIT)
        port = self.listener.sockets[0].getsockname()[1]
        return {"server": f"http://127.0.0.1:{port}", "username": self.username, "password": self.password}

    def matches(self, authority):
        try:
            if any(ord(c) < 33 for c in authority) or "\\" in authority:
                return False
            parsed = urlsplit("https://" + authority)
            return (parsed.hostname == self.host and parsed.port == self.port
                    and parsed.username is None and parsed.password is None
                    and not (parsed.path or parsed.query or parsed.fragment))
        except ValueError:
            return False

    def http_request(self, method, target, version, headers):
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            return None
        try:
            parsed = urlsplit(target)
            if (parsed.scheme != "http" or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None
                    or parsed.fragment or "\\" in target or any(ord(c) < 33 for c in target)):
                return None
            if b"content-length" in headers and (not headers[b"content-length"].isdigit() or b"transfer-encoding" in headers):
                return None
            if headers.get(b"transfer-encoding", b"chunked").lower() != b"chunked":
                return None
            path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
            host = parsed.netloc
            upgrade = headers.get(b"upgrade", b"").lower() == b"websocket"
            forwarded = [f"{method} {path} {version}".encode("ascii"), b"host: " + host.encode("ascii")]
            forwarded.extend(name + b": " + value for name, value in headers.items()
                             if name not in {b"host", b"connection", b"upgrade"} and not name.startswith(b"proxy-"))
            forwarded.append(b"connection: Upgrade" if upgrade else b"connection: close")
            if upgrade:
                forwarded.append(b"upgrade: websocket")
            return b"\r\n".join(forwarded) + b"\r\n\r\n"
        except (ValueError, UnicodeError):
            return None

    async def tunnel_request(self, reader, authority):
        # Chromium uses CONNECT for both ws:// and TLS. Select the exact
        # origin from the protocol before opening any target TCP connection.
        prefix = await asyncio.wait_for(reader.readexactly(5), 5)
        if prefix[0] == 22 and prefix[1] == 3 and prefix[2] <= 4 and 0 < int.from_bytes(prefix[3:5], "big") <= 18432:
            return "https", prefix
        if prefix != b"GET /":
            return None, None
        header = prefix + await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        if len(header) > HEADER_LIMIT:
            return None, None
        lines = header[:-4].split(b"\r\n")
        method, path, version = lines[0].decode("ascii").split(" ")
        headers = {}
        for line in lines[1:]:
            name, value = line.split(b":", 1)
            name = name.lower()
            if name in headers or not name or any(c not in HEADER_NAME for c in name):
                return None, None
            headers[name] = value.strip()
        expected = urlsplit("http://" + authority)
        received = urlsplit("http://" + headers.get(b"host", b"").decode("ascii"))
        if (version != "HTTP/1.1" or not path.startswith("/")
                or (received.hostname, received.port or 80) != (expected.hostname, expected.port)
                or received.username is not None or received.password is not None
                or received.path or received.query or received.fragment
                or headers.get(b"upgrade", b"").lower() != b"websocket"
                or b"upgrade" not in {item.strip().lower() for item in headers.get(b"connection", b"").split(b",")}
                or b"content-length" in headers or b"transfer-encoding" in headers):
            return None, None
        forwarded = self.http_request(method, "http://" + authority + path, version, headers)
        return ("http", forwarded) if forwarded else (None, None)

    async def reply(self, writer, code):
        challenge = b'Proxy-Authenticate: Basic realm="session"\r\n' if code == 407 else b""
        writer.write(f"HTTP/1.1 {code} \r\n".encode() + challenge + b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        await asyncio.wait_for(writer.drain(), 2)

    async def pipe(self, reader, writer):
        while not self.closed and self.enabled():
            try:
                chunk = await asyncio.wait_for(reader.read(65536), 0.5)
            except TimeoutError:
                continue
            if not chunk or not self.enabled() or self.closed:
                return
            writer.write(chunk)
            await asyncio.wait_for(writer.drain(), 2)

    async def accept(self, reader, writer):
        task = asyncio.current_task()
        if self.closed or len(self.tasks) >= 64:
            writer.close()
            return
        self.tasks.add(task)
        self.writers.add(writer)
        upstream = None
        pipes = []
        try:
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            if len(header) > HEADER_LIMIT:
                return
            lines = header[:-4].split(b"\r\n")
            method, authority, version = lines[0].decode("ascii").split(" ")
            headers = {}
            for line in lines[1:]:
                name, value = line.split(b":", 1)
                name = name.lower()
                if name in headers or not name or any(c not in HEADER_NAME for c in name):
                    return
                headers[name] = value.strip()
            if not hmac.compare_digest(headers.get(b"proxy-authorization", b""), self.authorization):
                await self.reply(writer, 407)
                return
            connect = method == "CONNECT"
            destination = urlsplit("https://" + authority if connect else authority)
            scheme = destination.scheme
            port = destination.port if destination.port is not None else (443 if scheme == "https" else 80)
            valid = (scheme in {"http", "https"} and destination.hostname
                     and destination.username is None and destination.password is None
                     and not destination.fragment and "\\" not in authority
                     and not any(ord(c) < 33 for c in authority) and 1 <= port <= 65535)
            if connect:
                valid = valid and not (destination.path or destination.query) and destination.port is not None
            forwarded = None if connect else self.http_request(method, authority, version, headers)
            if (not valid or version not in {"HTTP/1.0", "HTTP/1.1"} or not self.enabled() or self.closed
                    or (not connect and forwarded is None)):
                self.blocked_destination = True
                await self.reply(writer, 403)
                return
            if connect:
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await asyncio.wait_for(writer.drain(), 2)
                scheme, forwarded = await self.tunnel_request(reader, authority)
                if scheme is None:
                    self.blocked_destination = True
                    return
            address = None
            if (scheme, destination.hostname, port) == (self.scheme, self.host, self.port):
                address = self.address
            elif self.resolve:
                address = await self.resolve(scheme, destination.hostname, port)
            if not address or not self.enabled() or self.closed:
                self.blocked_destination = True
                await self.reply(writer, 403)
                return
            # Dial only literal IPs from the administrator's configured origins.
            remote, upstream = await asyncio.wait_for(asyncio.open_connection(address, port), 5)
            self.writers.add(upstream)
            if not self.enabled() or self.closed:
                return
            upstream.write(forwarded)
            await asyncio.wait_for(upstream.drain(), 2)
            pipes = [asyncio.create_task(self.pipe(reader, upstream)), asyncio.create_task(self.pipe(remote, writer))]
            await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
        except (ValueError, UnicodeError, OSError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            for item in pipes:
                item.cancel()
            await asyncio.gather(*pipes, return_exceptions=True)
            for item in (writer, upstream):
                if item:
                    self.writers.discard(item)
                    item.close()
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(item.wait_closed(), 1)
            self.tasks.discard(task)

    async def stop(self):
        self.closed = True
        if self.listener:
            self.listener.close()
        for writer in list(self.writers):
            writer.close()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.listener:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.listener.wait_closed(), 2)
        self.username = self.password = ""
        self.authorization = b""
