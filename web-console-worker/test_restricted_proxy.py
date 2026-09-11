import asyncio
import unittest
from unittest.mock import AsyncMock

from restricted_proxy import PinnedProxy


class PinnedProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.enabled = False
        self.hits = 0
        self.upstream_tasks = set()
        self.upstream_writers = set()

        async def echo(reader, writer):
            task = asyncio.current_task()
            self.upstream_tasks.add(task)
            self.upstream_writers.add(writer)
            self.hits += 1
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                self.upstream_writers.discard(writer)
                self.upstream_tasks.discard(task)

        self.server = await asyncio.start_server(echo, '127.0.0.1', 0)
        self.port = self.server.sockets[0].getsockname()[1]
        # Test-only loopback fixture. Production pins validated unicast addresses.
        self.proxy = PinnedProxy('console.invalid', self.port, '127.0.0.1', lambda: self.enabled)
        await self.proxy.start()
        self.proxy_port = self.proxy.listener.sockets[0].getsockname()[1]
        self.clients = []

    async def asyncTearDown(self):
        await asyncio.wait_for(self.proxy.stop(), 4)
        for writer in self.clients:
            writer.close()
            await writer.wait_closed()
        for writer in list(self.upstream_writers):
            writer.close()
        await asyncio.gather(*list(self.upstream_tasks), return_exceptions=True)
        self.server.close()
        await asyncio.wait_for(self.server.wait_closed(), 2)

    async def connect(self, authority=None, auth=True, method='CONNECT'):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.proxy_port)
        self.clients.append(writer)
        authority = authority or f'console.invalid:{self.port}'
        authorization = b'Proxy-Authorization: ' + self.proxy.authorization + b'\r\n' if auth else b''
        writer.write(f'{method} {authority} HTTP/1.1\r\n'.encode() + authorization + b'\r\n')
        await writer.drain()
        response = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2)
        return response, reader, writer

    async def test_requires_authentication_and_recording_activation(self):
        response, _, _ = await self.connect(auth=False)
        self.assertIn(b'407', response)
        response, _, _ = await self.connect()
        self.assertIn(b'403', response)
        self.assertEqual(self.hits, 0)

    async def test_redirect_destinations_and_plain_http_never_reach_upstream(self):
        self.enabled = True
        for authority in (f'127.0.0.1:{self.port}', f'other.invalid:{self.port}',
                          'console.invalid:1', '169.254.169.254:443',
                          f'user@console.invalid:{self.port}', f'console.invalid:{self.port}/path'):
            response, reader, writer = await self.connect(authority)
            if b'200' in response:
                writer.write(b'\x16\x03\x01\x00\x10')
                await writer.drain()
                response = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2)
            self.assertIn(b'403', response, authority)
        response, _, _ = await self.connect(f'http://console.invalid:{self.port}/', method='GET')
        self.assertIn(b'403', response)
        self.assertEqual(self.hits, 0)

    async def test_transport_uses_pinned_ip_and_closes_when_lease_expires(self):
        self.enabled = True
        response, reader, writer = await self.connect()
        self.assertIn(b'200', response)
        # The deliberately unresolvable CONNECT hostname must not be looked up.
        writer.write(b'\x16\x03\x01\x00\x10opaque-tls-bytes!')
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(22), 2), b'\x16\x03\x01\x00\x10opaque-tls-bytes!')
        self.assertEqual(self.hits, 1)
        self.enabled = False
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')

    async def test_stop_with_live_tunnel_and_pending_handshake_does_not_deadlock(self):
        self.enabled = True
        _, reader, _ = await self.connect()
        pending_reader, pending_writer = await asyncio.open_connection('127.0.0.1', self.proxy_port)
        self.clients.append(pending_writer)
        await asyncio.wait_for(self.proxy.stop(), 3)
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        self.assertEqual(await asyncio.wait_for(pending_reader.read(), 2), b'')
        self.assertFalse(self.proxy.tasks)
        self.assertFalse(self.proxy.writers)
        with self.assertRaises(OSError):
            await asyncio.open_connection('127.0.0.1', self.proxy_port)

    async def test_explicit_additional_origin_is_connected_without_resolving_others(self):
        self.enabled = True
        async def resolve(scheme, host, port):
            return "127.0.0.1" if (scheme, host, port) == ("https", "sso.invalid", self.port) else None
        self.proxy.resolve = AsyncMock(side_effect=resolve)
        response, reader, writer = await self.connect(f"sso.invalid:{self.port}")
        self.assertIn(b"200", response)
        writer.write(b"\x16\x03\x01\x00\x01x"); await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(6), 2), b"\x16\x03\x01\x00\x01x")
        response, reader, writer = await self.connect(f"unlisted.invalid:{self.port}")
        writer.write(b"\x16\x03\x01\x00\x01x"); await writer.drain()
        self.assertIn(b"403", await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2))
        self.assertEqual(self.hits, 1)

    async def test_http_request_rewrites_authority_and_strips_proxy_credentials(self):
        self.enabled = True
        self.proxy.scheme = "http"
        response, _, _ = await self.connect(f"http://console.invalid:{self.port}/ui?x=1", method="GET")
        self.assertTrue(response.startswith(b"GET /ui?x=1 HTTP/1.1"))
        self.assertIn(f"host: console.invalid:{self.port}".encode(), response)
        self.assertIn(b"connection: close", response)
        self.assertNotIn(b"Proxy-Authorization", response)
        self.assertNotIn(self.proxy.authorization, response)
        response, _, _ = await self.connect(f"http://other.invalid:{self.port}/", method="GET")
        self.assertIn(b"403", response)
        self.assertEqual(self.hits, 1)


    async def test_plain_websocket_connect_uses_only_exact_http_origin(self):
        self.enabled = True
        self.proxy.scheme = "http"
        response, reader, writer = await self.connect()
        self.assertIn(b"200", response)
        writer.write(f"GET /socket?x=1 HTTP/1.1\r\nHost: console.invalid:{self.port}\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nProxy-Authorization: secret\r\n\r\n".encode())
        await writer.drain()
        forwarded = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertTrue(forwarded.startswith(b"GET /socket?x=1 HTTP/1.1"))
        self.assertIn(b"upgrade: websocket", forwarded)
        self.assertNotIn(b"secret", forwarded)
        self.assertEqual(self.hits, 1)

    async def test_tls_cannot_use_http_only_origin_and_ws_cannot_use_https_only_origin(self):
        self.enabled = True
        for configured in ("http", "https"):
            self.proxy.scheme = configured
            _, reader, writer = await self.connect()
            payload = b"\x16\x03\x01\x00\x01x" if configured == "http" else f"GET /socket HTTP/1.1\r\nHost: console.invalid:{self.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".encode()
            writer.write(payload); await writer.drain()
            self.assertIn(b"403", await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2))
        self.assertEqual(self.hits, 0)

    async def test_tunneled_plain_http_or_mismatched_websocket_host_never_dials(self):
        self.enabled = True
        self.proxy.scheme = "http"
        for host, upgrade in (("other.invalid", True), ("console.invalid", False)):
            _, reader, writer = await self.connect()
            extra = "Upgrade: websocket\r\nConnection: Upgrade\r\n" if upgrade else ""
            writer.write(f"GET /socket HTTP/1.1\r\nHost: {host}:{self.port}\r\n{extra}\r\n".encode())
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(self.hits, 0)
