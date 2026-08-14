import asyncio
import unittest

from app.tunnel import TunnelHub


class FakeWebSocket:
    def __init__(self):
        self.control_messages: asyncio.Queue[dict] = asyncio.Queue()
        self.incoming: asyncio.Queue[dict] = asyncio.Queue()
        self.outgoing: asyncio.Queue[bytes] = asyncio.Queue()
        self.closed = False

    async def send_json(self, value: dict) -> None:
        await self.control_messages.put(value)

    async def send_bytes(self, value: bytes) -> None:
        await self.outgoing.put(value)

    async def receive(self) -> dict:
        return await self.incoming.get()

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = True


class TunnelHubTests(unittest.IsolatedAsyncioTestCase):
    async def test_listener_requires_online_agent(self):
        hub = TunnelHub(bind_host="127.0.0.1")
        with self.assertRaises(ConnectionError):
            await hub.create_listener("session-1", "agent-1", "ssh")

    async def test_agent_stream_is_prepared_before_tcp_relay_is_returned(self):
        closed: list[tuple[str, str]] = []

        async def on_closed(session_id: str, reason: str) -> None:
            closed.append((session_id, reason))

        hub = TunnelHub(bind_host="127.0.0.1", connect_timeout_seconds=2, closed_callback=on_closed)
        control = FakeWebSocket()
        stream = FakeWebSocket()
        await hub.register_control("agent-1", control)
        listener_task = asyncio.create_task(hub.create_listener("session-1", "agent-1", "ssh"))
        instruction = await asyncio.wait_for(control.control_messages.get(), timeout=2)
        self.assertEqual(instruction, {"type": "open", "session_id": "session-1", "protocol": "ssh", "port": 22})
        self.assertFalse(listener_task.done())
        attached = asyncio.create_task(hub.attach_stream("session-1", "agent-1", stream))
        port = await asyncio.wait_for(listener_task, timeout=2)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        writer.write(b"client-to-agent")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(stream.outgoing.get(), timeout=2), b"client-to-agent")

        await stream.incoming.put({"type": "websocket.receive", "bytes": b"agent-to-client"})
        self.assertEqual(await asyncio.wait_for(reader.readexactly(15), timeout=2), b"agent-to-client")
        await stream.incoming.put({"type": "websocket.disconnect"})
        await asyncio.wait_for(attached, timeout=2)
        writer.close()
        await writer.wait_closed()
        self.assertTrue(stream.closed)
        self.assertEqual(closed[-1], ("session-1", "closed"))

    async def test_listener_fails_before_guacamole_when_agent_stream_times_out(self):
        closed: list[tuple[str, str]] = []

        async def on_closed(session_id: str, reason: str) -> None:
            closed.append((session_id, reason))

        hub = TunnelHub(bind_host="127.0.0.1", connect_timeout_seconds=0.01, closed_callback=on_closed)
        control = FakeWebSocket()
        await hub.register_control("agent-1", control)
        with self.assertRaisesRegex(ConnectionError, "did not prepare"):
            await hub.create_listener("session-timeout", "agent-1", "ssh")
        self.assertEqual(closed[-1], ("session-timeout", "agent-stream-timeout"))


if __name__ == "__main__":
    unittest.main()
