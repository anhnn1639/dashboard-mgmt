"""Per-session CONNECT transport to one validated HTTPS host and pinned IP.

TLS stays end-to-end with Chromium. No request body, credential or URL logging.
Redirects cannot change the destination, even when browser routing is skipped.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hmac
import secrets
from urllib.parse import urlsplit


class PinnedProxy:
    def __init__(self, host, port, address, enabled):
        self.host, self.port, self.address = host, port, address
        self.enabled = enabled
        self.username, self.password = secrets.token_hex(16), secrets.token_hex(24)
        self.authorization = b"Basic " + base64.b64encode(f"{self.username}:{self.password}".encode())
        self.listener = None
        self.tasks = set()
        self.writers = set()
        self.closed = False

    async def start(self):
        self.listener = await asyncio.start_server(self.accept, "127.0.0.1", 0, limit=8192)
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
            if len(header) > 8192:
                return
            lines = header[:-4].split(b"\r\n")
            method, authority, version = lines[0].decode("ascii").split(" ")
            headers = {}
            for line in lines[1:]:
                name, value = line.split(b":", 1)
                name = name.lower()
                if name in headers:
                    return
                headers[name] = value.strip()
            if not hmac.compare_digest(headers.get(b"proxy-authorization", b""), self.authorization):
                await self.reply(writer, 407)
                return
            if (method != "CONNECT" or version not in {"HTTP/1.0", "HTTP/1.1"}
                    or not self.matches(authority) or not self.enabled() or self.closed):
                await self.reply(writer, 403)
                return
            # Only the prevalidated literal IP is dialed: never resolve the
            # CONNECT authority, a redirect destination or changed DNS answer.
            remote, upstream = await asyncio.wait_for(asyncio.open_connection(self.address, self.port), 5)
            self.writers.add(upstream)
            if not self.enabled() or self.closed:
                return
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await asyncio.wait_for(writer.drain(), 2)
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
