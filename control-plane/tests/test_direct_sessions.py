import asyncio
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app.direct_sessions import DirectSessionHub, discover_host_key


class DirectSessionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.callback = AsyncMock()
        self.hub = DirectSessionHub("127.0.0.1", self.callback)

    async def asyncTearDown(self):
        for identifier in list(self.hub.relays):
            await self.hub.cancel(identifier)

    async def test_only_fixed_unicast_ipv4_and_valid_port(self):
        for address, port in [("localhost", 22), ("127.0.0.1", 22), ("169.254.169.254", 22), ("224.0.0.1", 22), ("0.0.0.0", 22), ("10.8.1.2", 0), ("10.8.1.2", 65536)]:
            with self.assertRaises(ValueError):
                await self.hub.create_listener("id", "target", address, port)
        self.assertEqual(self.hub.relays, {})

    async def test_pending_limit_and_expiry_release_listener(self):
        for index in range(4):
            await self.hub.create_listener(str(index), "target", "10.8.1.2", 22)
        with self.assertRaises(ConnectionError):
            await self.hub.create_listener("fifth", "target", "10.8.1.2", 22)
        self.hub.ttl = .001
        await asyncio.gather(*(self.hub.expire(str(index)) for index in range(4)))
        self.assertFalse(self.hub.relays)
        self.assertEqual(self.callback.await_count, 4)

    async def test_single_use_bidirectional_relay_without_external_network(self):
        finished = asyncio.Event()

        async def echo(reader, writer):
            writer.write(b"SSH-test-banner")
            await writer.drain()
            data = await reader.read(1024)
            writer.write(data)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            finished.set()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        open_connection = asyncio.open_connection
        upstream_port = upstream.sockets[0].getsockname()[1]

        async def local_upstream(host, port):
            self.assertEqual((host, port), ("10.8.1.2", 2222))
            return await open_connection("127.0.0.1", upstream_port)

        try:
            port = await self.hub.create_listener("id", "target", "10.8.1.2", 2222)
            with patch("app.direct_sessions.asyncio.open_connection", side_effect=local_upstream):
                reader, writer = await open_connection("127.0.0.1", port)
                self.assertEqual(await asyncio.wait_for(reader.readexactly(15), 2), b"SSH-test-banner")
                writer.write(b"test-paste-command")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(18), 2), b"test-paste-command")
                await asyncio.wait_for(finished.wait(), 2)
                self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
                writer.close()
                await writer.wait_closed()
            for _ in range(20):
                if not self.hub.relays:
                    break
                await asyncio.sleep(.01)
            self.assertFalse(self.hub.relays)
            with self.assertRaises(OSError):
                await open_connection("127.0.0.1", port)
            self.callback.assert_awaited_once_with("id", "closed")
        finally:
            upstream.close()
            await upstream.wait_closed()

    async def test_discovery_is_no_shell_and_prefers_ecdsa_compatible_key(self):
        process = AsyncMock()
        process.communicate.return_value = (b"10.8.1.2 ssh-rsa dGVzdA==\n10.8.1.2 ecdsa-sha2-nistp256 dGVzdA==\n", b"")
        with patch("app.direct_sessions.asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=process) as execute:
            self.assertEqual(await discover_host_key("10.8.1.2", 2222), "ecdsa-sha2-nistp256 dGVzdA==")
            self.assertEqual(execute.call_args.args[-1], "10.8.1.2")
            self.assertNotIn("shell", execute.call_args.kwargs)

    async def test_smoke_protocol_encoder_and_parser(self):
        path = Path(__file__).resolve().parents[2] / "tests" / "ssh-smoke" / "verify.py"
        spec = importlib.util.spec_from_file_location("ssh_smoke", path)
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        self.assertEqual(smoke.instruction("select", "ssh"), b"6.select,3.ssh;")
        reader = asyncio.StreamReader()
        reader.feed_data(smoke.instruction("args", "VERSION_1_5_0", "hostname", "port"))
        reader.feed_eof()
        self.assertEqual(await smoke.read_instruction(reader), ["args", "VERSION_1_5_0", "hostname", "port"])
