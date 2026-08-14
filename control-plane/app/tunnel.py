from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Awaitable, Callable

from fastapi import WebSocket


TunnelClosedCallback = Callable[[str, str], Awaitable[None]]


@dataclass
class AgentChannel:
    websocket: WebSocket
    connected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class PendingTunnel:
    session_id: str
    agent_id: str
    protocol: str
    target_port: int
    listener: asyncio.AbstractServer
    agent_websocket: asyncio.Future[WebSocket]
    finished: asyncio.Future[None]
    client_connected: bool = False
    expiry_task: asyncio.Task[None] | None = None


class TunnelHub:
    """Pair an internal, per-session TCP listener with an agent WebSocket.

    The TCP listener is intended to be reachable only by guacd on the private
    Docker session network. The agent always initiates the TLS connection and
    is never asked to connect to an arbitrary host or port.
    """

    def __init__(
        self,
        *,
        bind_host: str = "0.0.0.0",
        listener_ttl_seconds: int = 120,
        connect_timeout_seconds: int = 20,
        max_sessions_per_agent: int = 4,
        closed_callback: TunnelClosedCallback | None = None,
    ) -> None:
        self.bind_host = bind_host
        self.listener_ttl_seconds = listener_ttl_seconds
        self.connect_timeout_seconds = connect_timeout_seconds
        self.max_sessions_per_agent = max_sessions_per_agent
        self.closed_callback = closed_callback
        self._agents: dict[str, AgentChannel] = {}
        self._pending: dict[str, PendingTunnel] = {}

    def is_online(self, agent_id: str) -> bool:
        return agent_id in self._agents

    async def register_control(self, agent_id: str, websocket: WebSocket) -> None:
        previous = self._agents.get(agent_id)
        self._agents[agent_id] = AgentChannel(websocket)
        if previous and previous.websocket is not websocket:
            with contextlib.suppress(Exception):
                await previous.websocket.close(code=1012, reason="Agent reconnected")

    async def unregister_control(self, agent_id: str, websocket: WebSocket) -> None:
        channel = self._agents.get(agent_id)
        if not channel or channel.websocket is not websocket:
            return
        self._agents.pop(agent_id, None)
        for pending in list(self._pending.values()):
            if pending.agent_id == agent_id:
                await self.cancel(pending.session_id, "agent-disconnected")

    async def create_listener(self, session_id: str, agent_id: str, protocol: str) -> int:
        if protocol not in {"ssh", "rdp"}:
            raise ValueError("Unsupported tunnel protocol")
        if agent_id not in self._agents:
            raise ConnectionError("Agent tunnel is offline")
        if sum(1 for item in self._pending.values() if item.agent_id == agent_id) >= self.max_sessions_per_agent:
            raise ConnectionError("Agent tunnel session limit reached")
        if session_id in self._pending:
            raise ValueError("Tunnel session already exists")

        loop = asyncio.get_running_loop()
        agent_websocket: asyncio.Future[WebSocket] = loop.create_future()
        finished: asyncio.Future[None] = loop.create_future()
        target_port = 22 if protocol == "ssh" else 3389

        def accepted(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            asyncio.create_task(self._serve_tcp(session_id, reader, writer))

        listener = await asyncio.start_server(accepted, self.bind_host, 0, backlog=1)
        pending = PendingTunnel(
            session_id=session_id,
            agent_id=agent_id,
            protocol=protocol,
            target_port=target_port,
            listener=listener,
            agent_websocket=agent_websocket,
            finished=finished,
        )
        self._pending[session_id] = pending
        pending.expiry_task = asyncio.create_task(self._expire(session_id))
        sockets = listener.sockets or []
        if not sockets:
            await self.cancel(session_id, "listener-failed")
            raise OSError("Tunnel listener has no socket")
        return int(sockets[0].getsockname()[1])

    async def attach_stream(self, session_id: str, agent_id: str, websocket: WebSocket) -> None:
        pending = self._pending.get(session_id)
        if not pending or pending.agent_id != agent_id or pending.agent_websocket.done():
            await websocket.close(code=4404, reason="Tunnel session not found")
            return
        pending.agent_websocket.set_result(websocket)
        await asyncio.shield(pending.finished)

    async def cancel(self, session_id: str, reason: str = "cancelled") -> None:
        pending = self._pending.pop(session_id, None)
        if not pending:
            return
        pending.listener.close()
        with contextlib.suppress(Exception):
            await pending.listener.wait_closed()
        if pending.expiry_task and pending.expiry_task is not asyncio.current_task():
            pending.expiry_task.cancel()
        if not pending.agent_websocket.done():
            pending.agent_websocket.cancel()
        elif not pending.agent_websocket.cancelled():
            with contextlib.suppress(Exception):
                await pending.agent_websocket.result().close(code=1011, reason=reason)
        if not pending.finished.done():
            pending.finished.set_result(None)
        await self._notify_closed(session_id, reason)

    async def _expire(self, session_id: str) -> None:
        await asyncio.sleep(self.listener_ttl_seconds)
        await self.cancel(session_id, "listener-expired")

    async def _serve_tcp(self, session_id: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        pending = self._pending.get(session_id)
        if not pending or pending.client_connected:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return

        pending.client_connected = True
        pending.listener.close()
        if pending.expiry_task:
            pending.expiry_task.cancel()

        channel = self._agents.get(pending.agent_id)
        if not channel:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            await self.cancel(session_id, "agent-offline")
            return

        try:
            async with channel.send_lock:
                await channel.websocket.send_json(
                    {
                        "type": "open",
                        "session_id": pending.session_id,
                        "protocol": pending.protocol,
                        "port": pending.target_port,
                    }
                )
            agent_websocket = await asyncio.wait_for(
                asyncio.shield(pending.agent_websocket),
                timeout=self.connect_timeout_seconds,
            )
            await self._bridge(reader, writer, agent_websocket)
            reason = "closed"
        except (TimeoutError, asyncio.TimeoutError):
            reason = "agent-stream-timeout"
        except Exception:
            reason = "bridge-error"
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            await self.cancel(session_id, reason)

    async def _bridge(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, websocket: WebSocket) -> None:
        async def tcp_to_websocket() -> None:
            while data := await reader.read(64 * 1024):
                await websocket.send_bytes(data)

        async def websocket_to_tcp() -> None:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    return
                data = message.get("bytes")
                if data is None:
                    raise ValueError("Tunnel streams accept binary frames only")
                writer.write(data)
                await writer.drain()

        tasks = {asyncio.create_task(tcp_to_websocket()), asyncio.create_task(websocket_to_tcp())}
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            task.result()

    async def _notify_closed(self, session_id: str, reason: str) -> None:
        if self.closed_callback:
            with contextlib.suppress(Exception):
                await self.closed_callback(session_id, reason)
