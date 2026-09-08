"""Single-use internal SSH relays for explicitly registered, agentless targets."""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable


async def discover_host_key(address: str, port: int) -> str:
    ip = ipaddress.ip_address(address)
    if ip.version != 4 or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise ValueError("Invalid SSH destination")
    # No shell; only the fixed DB endpoint. First use pins the observed key.
    process = await asyncio.create_subprocess_exec(
        "ssh-keyscan", "-T", "5", "-p", str(port), "-t", "ecdsa,ed25519,rsa", str(ip),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        output, _ = await asyncio.wait_for(process.communicate(), 18)
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    keys = []
    for line in output.decode("ascii", errors="ignore").splitlines():
        parts = line.split()
        if len(parts) == 3 and re.fullmatch(r"(?:ecdsa-sha2-nistp(?:256|384|521)|ssh-ed25519|ssh-rsa)", parts[1]) and re.fullmatch(r"[A-Za-z0-9+/=]+", parts[2]):
            keys.append(" ".join(parts[1:]))
    if not keys:
        raise ConnectionError("Không đọc được khóa máy chủ SSH; kiểm tra IP, cổng và firewall.")
    return sorted(keys, key=lambda key: (not key.startswith("ecdsa-"), not key.startswith("ssh-ed25519"), key))[0]


@dataclass
class Relay:
    target_id: str
    host: str
    port: int
    listener: asyncio.AbstractServer
    expiry: asyncio.Task | None = None
    connected: bool = False
    writers: list[asyncio.StreamWriter] = field(default_factory=list)


class DirectSessionHub:
    def __init__(self, bind_host: str, closed_callback: Callable[[str, str], Awaitable[None]], ttl: float = 120, duration: float = 3600):
        self.bind_host, self.closed_callback = bind_host, closed_callback
        self.ttl, self.duration = ttl, duration
        self.relays: dict[str, Relay] = {}
        self.lock = asyncio.Lock()

    async def create_listener(self, session_id: str, target_id: str, address: str, port: int) -> int:
        # Network destinations are immutable for the lifetime of this relay.
        ip = ipaddress.ip_address(address)
        if ip.version != 4 or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or not 1 <= port <= 65535:
            raise ValueError("Invalid SSH destination")
        async with self.lock:
            if session_id in self.relays or len(self.relays) >= 64 or sum(r.target_id == target_id for r in self.relays.values()) >= 4:
                raise ConnectionError("Đã đạt giới hạn phiên SSH đang mở.")
            listener = await asyncio.start_server(lambda r, w: asyncio.create_task(self.serve(session_id, r, w)), self.bind_host, 0, backlog=1)
            relay = Relay(target_id, str(ip), port, listener)
            self.relays[session_id] = relay
            relay.expiry = asyncio.create_task(self.expire(session_id))
            return int(listener.sockets[0].getsockname()[1])

    async def expire(self, session_id: str):
        await asyncio.sleep(self.ttl)
        await self.cancel(session_id, "listener-expired")

    async def cancel(self, session_id: str, reason="closed"):
        relay = self.relays.pop(session_id, None)
        if not relay:
            return
        relay.listener.close()
        if relay.expiry and relay.expiry is not asyncio.current_task():
            relay.expiry.cancel()
        for writer in relay.writers:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        # Python 3.12 Server.wait_closed waits for accepted transports too.
        # Close their writers first; otherwise EOF can deadlock cleanup.
        await relay.listener.wait_closed()
        await self.closed_callback(session_id, reason)

    async def serve(self, session_id, reader, writer):
        relay = self.relays.get(session_id)
        if not relay or relay.connected:
            writer.close()
            return
        relay.connected = True
        relay.listener.close()
        relay.expiry.cancel()
        relay.writers.append(writer)
        tasks = []
        reason = "closed"
        try:
            upstream, output = await asyncio.wait_for(asyncio.open_connection(relay.host, relay.port), 15)
            relay.writers.append(output)

            async def copy(source, target):
                while data := await source.read(65536):
                    target.write(data)
                    await target.drain()

            tasks = [asyncio.create_task(copy(reader, output)), asyncio.create_task(copy(upstream, writer))]
            done, _ = await asyncio.wait(tasks, timeout=self.duration, return_when=asyncio.FIRST_COMPLETED)
            if not done:
                reason = "session-expired"
            for task in done:
                task.result()
        except Exception:
            reason = "connection-failed"
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self.cancel(session_id, reason)
