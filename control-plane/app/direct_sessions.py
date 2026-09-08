"""Single-use internal SSH relays for explicitly registered, agentless targets."""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable


class SSHProbeError(ConnectionError):
    """A fixed public message/code, never raw SSH stderr or a remote banner."""
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _host_keys(output: bytes, address: str, port: int) -> list[str]:
    expected = address if port == 22 else f"[{address}]:{port}"
    keys = []
    for line in output.decode("ascii", errors="ignore").splitlines():
        parts = line.split()
        if (len(parts) == 3 and parts[0] == expected
                and re.fullmatch(r"(?:ecdsa-sha2-nistp(?:256|384|521)|ssh-ed25519|ssh-rsa)", parts[1])
                and re.fullmatch(r"[A-Za-z0-9+/=]+", parts[2])):
            keys.append(" ".join(parts[1:]))
    # Match guacd's host-key preference on servers offering several key types.
    return sorted(keys, key=lambda key: (not key.startswith("ecdsa-"), not key.startswith("ssh-ed25519"), key))


async def _run_probe(*args: str) -> tuple[bytes, bytes]:
    try:
        process = await asyncio.create_subprocess_exec(
            *args, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise SSHProbeError("probe_unavailable", "Bộ kết nối SSH chưa đầy đủ. Cần rebuild API với openssh-client.") from exc

    async def read_bounded(stream):
        data = b""
        while len(data) <= 65536:
            chunk = await stream.read(65537 - len(data))
            if not chunk:
                return data
            data += chunk
        raise SSHProbeError("invalid_response", "Thiết bị trả phản hồi SSH quá lớn hoặc không hợp lệ.")

    tasks = [asyncio.create_task(read_bounded(process.stdout)), asyncio.create_task(read_bounded(process.stderr))]
    try:
        output, errors = await asyncio.wait_for(asyncio.gather(*tasks), 18)
        await asyncio.wait_for(process.wait(), 2)
        return output, errors
    except TimeoutError as exc:
        raise SSHProbeError("timeout", "Thiết bị không hoàn tất bắt tay SSH đúng hạn. Kiểm tra dịch vụ SSH và đường truyền.") from exc
    finally:
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # Drain both pipes after killing the bounded probe. wait() alone can
        # deadlock when an oversized banner has paused a StreamReader transport.
        await process.communicate()


def _probe_failure(errors: bytes) -> SSHProbeError:
    diagnostic = errors.decode("ascii", errors="ignore").lower()
    if any(marker in diagnostic for marker in ("kex: algorithm: (no match)", "no matching key exchange method", "no matching host key type", "no matching cipher", "no matching mac")):
        return SSHProbeError("algorithms_unsupported", "Thiết bị không có thuật toán SSH tương thích. Chế độ cũ chỉ hỗ trợ thêm Group14-SHA1 và RSA/SHA1; không hỗ trợ SSHv1, DSA, Group1 hoặc CBC/3DES. Cần nâng firmware nếu thiết bị chỉ có các thuật toán này.")
    if "connection refused" in diagnostic:
        return SSHProbeError("connection_refused", "Thiết bị từ chối cổng SSH. Kiểm tra cổng và dịch vụ SSH trên thiết bị.")
    if any(marker in diagnostic for marker in ("timed out", "no route to host", "network is unreachable")):
        return SSHProbeError("unreachable", "Không tới được SSH từ API. Kiểm tra IP, cổng và firewall trên đường đi của container API.")
    return SSHProbeError("handshake_failed", "Không đọc được khóa máy chủ SSH. Thiết bị đóng kết nối hoặc chưa hoàn tất bắt tay SSH; kiểm tra log SSH trên thiết bị.")


async def _discover_legacy_host_key(address: str, port: int) -> str:
    # Only called for an individually opted-in DB target after modern KEX fails.
    # ssh-keyscan cannot accept KexAlgorithms. This isolated SSHv2 probe has no
    # vault credentials, authentication, remote command or forwarding enabled.
    # The temporary file contains PUBLIC keys; durable TOFU pins stay in PG.
    with tempfile.TemporaryDirectory(prefix="tram-ssh-probe-") as directory:
        known_hosts = Path(directory) / "known_hosts"
        options = [
            "BatchMode=yes", "ConnectTimeout=8", "ConnectionAttempts=1",
            "StrictHostKeyChecking=accept-new", f"UserKnownHostsFile={known_hosts}",
            "GlobalKnownHostsFile=/dev/null", "HashKnownHosts=no", "UpdateHostKeys=no",
            "PreferredAuthentications=none", "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no", "PubkeyAuthentication=no",
            "HostbasedAuthentication=no", "GSSAPIAuthentication=no",
            "IdentityAgent=none", "IdentitiesOnly=yes", "IdentityFile=none",
            "CertificateFile=none", "ForwardAgent=no", "ClearAllForwardings=yes",
            "PermitLocalCommand=no", "ProxyCommand=none", "ProxyJump=none",
            # Minimal Cisco compatibility, scoped to this process/target only.
            # No group1, GEX-SHA1, CBC, 3DES, DSA or global ssh_config change.
            "KexAlgorithms=+diffie-hellman-group14-sha1",
            "HostKeyAlgorithms=ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
        ]
        args = ["ssh", "-v", "-2", "-F", "/dev/null", "-N", "-T", "-p", str(port), "-l", "tram-hostkey-probe"]
        for option in options:
            args.extend(("-o", option))
        try:
            _, errors = await _run_probe(*args, address)
        except SSHProbeError as exc:
            if exc.code != "timeout":
                raise
            # Servers accepting 'none' may keep -N open; the host key is written
            # before authentication. The bounded probe has already been killed.
            errors = b"Connection timed out"
        keys = []
        if known_hosts.exists() and known_hosts.stat().st_size <= 65536:
            keys = _host_keys(known_hosts.read_bytes(), address, port)
        if not keys:
            raise _probe_failure(errors)
        logging.getLogger(__name__).warning("SSH Group14/RSA SHA1 host-key compatibility used for %s:%s", address, port)
        return keys[0]


async def discover_host_key(address: str, port: int, *, legacy_compatibility: bool = False) -> str:
    ip = ipaddress.ip_address(address)
    if ip.version != 4 or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or not 1 <= port <= 65535:
        raise ValueError("Invalid SSH destination")
    # No shell; only the fixed DB endpoint. First use pins the observed key.
    output, errors = await _run_probe(
        "ssh-keyscan", "-v", "-T", "5", "-p", str(port), "-t", "ecdsa,ed25519,rsa", str(ip),
    )
    keys = _host_keys(output, str(ip), port)
    if keys:
        return keys[0]
    failure = _probe_failure(errors)
    if failure.code == "algorithms_unsupported":
        if legacy_compatibility:
            return await _discover_legacy_host_key(str(ip), port)
        raise SSHProbeError("legacy_opt_in_required", "Đã tới dịch vụ SSH nhưng không khớp thuật toán. Với thiết bị cũ, vào Sửa kết nối và bật Tương thích SSH cũ (Group14/RSA-SHA1) riêng cho thiết bị này.")
    raise failure


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
