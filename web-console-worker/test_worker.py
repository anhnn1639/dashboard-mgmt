import asyncio
import hashlib
import struct
import time
import unittest
import uuid
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

import browser_worker as w


class WorkerPolicyTests(unittest.TestCase):
    def test_exact_https_origin_and_safe_dns(self):
        target = "https://10.64.83.30/ui"
        for url in ("https://10.64.83.30/login", "wss://10.64.83.30/socket", "https://10.64.83.30:443/ui"):
            self.assertTrue(w.allowed_url(url, target))
        for url in ("http://10.64.83.30/ui", "https://10.64.83.31/ui", "https://10.64.83.30:8443/", "https://10.64.83.30.evil.test/", "https://u:p@10.64.83.30/", "file:///etc/passwd", "https://10.64.83.30\\@evil.test/"):
            self.assertFalse(w.allowed_url(url, target), url)
        for ip in ("127.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "224.1.2.3", "0.0.0.0"):
            self.assertFalse(w.safe_ip(ip), ip)
        self.assertTrue(w.safe_ip("10.64.83.30"))

    def test_internal_api_requires_secret_and_hides_validation_input(self):
        client = TestClient(w.app)
        with patch.dict(w.os.environ, {"GUACAMOLE_JSON_SECRET": "a" * 32}):
            self.assertEqual(client.get("/sessions/" + str(uuid.uuid4())).status_code, 401)
            headers = {"Authorization": "Bearer " + hashlib.sha256(("tram-web-console:" + "a" * 32).encode()).hexdigest()}
            response = client.post("/sessions", headers=headers, json={"target_url": "https://user:private-test-value@example.test/"})
            self.assertEqual(response.status_code, 422)
            self.assertNotIn("private-test-value", response.text)
            self.assertEqual(client.get("/docs").status_code, 404)

    def test_invalid_dimensions_and_host_resolver_injection(self):
        for url in ("https://host,MAP*evil/", "https://evil example/", "https://foo/*#fragment"):
            with self.assertRaises(ValidationError):
                w.CreateSession(session_id=uuid.uuid4(), target_url=url)
        with self.assertRaises(ValidationError):
            w.CreateSession(session_id=uuid.uuid4(), target_url="https://example.test/", width=7680)


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_rfb_authentication_single_use_and_activation_gate(self):
        desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(), target_url="https://console.test/", width=800, height=600))
        desktop.page = type("Page", (), {"keyboard": type("Keyboard", (), {"down": AsyncMock(), "up": AsyncMock(), "insert_text": AsyncMock()})(), "goto": AsyncMock()})()
        async def no_frames(_writer):
            await asyncio.Event().wait()
        desktop.frames = no_frames
        desktop.listener = await asyncio.start_server(desktop.accept, "127.0.0.1", 0)
        port = desktop.listener.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            self.assertEqual(await reader.readexactly(12), b"RFB 003.008\n")
            writer.write(b"RFB 003.008\n"); await writer.drain()
            self.assertEqual(await reader.readexactly(2), b"\x01\x02")
            writer.write(b"\x02"); await writer.drain()
            challenge = await reader.readexactly(16)
            writer.write(w.challenge_response(desktop.password, challenge)); await writer.drain()
            self.assertEqual(await reader.readexactly(4), b"\0\0\0\0")
            writer.write(b"\x01"); await writer.drain()
            header = await reader.readexactly(24)
            await reader.readexactly(struct.unpack(">I", header[20:24])[0])
            writer.write(b"\x04" + struct.pack(">B2xI", 1, ord("a"))); await writer.drain()
            await asyncio.sleep(0.02)
            desktop.page.keyboard.down.assert_not_awaited()
            desktop.page.goto.assert_not_awaited()
            await desktop.activate()
            await asyncio.sleep(0)
            desktop.page.goto.assert_awaited_once()
            writer.write(b"\x04" + struct.pack(">B2xI", 1, ord("a"))); await writer.drain()
            await asyncio.sleep(0.02)
            desktop.page.keyboard.down.assert_awaited_once_with("a")
            with self.assertRaises(OSError):
                await asyncio.open_connection("127.0.0.1", port)
        finally:
            writer.close(); await writer.wait_closed()
            await asyncio.wait_for(desktop.client_task, 2)
        self.assertEqual(desktop.status, "closed")

    async def test_route_stays_closed_until_activation_and_blocks_other_origins(self):
        desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(), target_url="https://console.test/"))
        route = type("Route", (), {"request": type("Request", (), {"url": "https://console.test/"})(), "continue_": AsyncMock(), "abort": AsyncMock()})()
        await desktop.route(route)
        route.abort.assert_awaited_once()
        desktop.status = "active"
        await desktop.route(route)
        route.continue_.assert_awaited_once()
        route.request.url = "https://sso-other.test/"
        await desktop.route(route)
        self.assertEqual(route.continue_.await_count, 1)


    async def test_expired_lease_blocks_input_routes_and_activation_immediately(self):
        desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(), target_url="https://console.test/"))
        desktop.status = "active"
        desktop.deadline = time.monotonic() - 1
        desktop.page = type("Page", (), {"keyboard": type("Keyboard", (), {"down": AsyncMock()})(),
            "mouse": type("Mouse", (), {"move": AsyncMock()})(), "goto": AsyncMock()})()
        route = type("Route", (), {"request": type("Request", (), {"url": desktop.url})(),
            "continue_": AsyncMock(), "abort": AsyncMock()})()
        websocket = type("Socket", (), {"url": "wss://console.test/socket", "close": AsyncMock()})()
        await desktop.key(ord("a"), True)
        await desktop.mouse(1, 80, 80)
        await desktop.route(route)
        await desktop.route_socket(websocket)
        desktop.page.keyboard.down.assert_not_awaited()
        desktop.page.mouse.move.assert_not_awaited()
        route.continue_.assert_not_awaited()
        route.abort.assert_awaited_once()
        websocket.close.assert_awaited_once()
        desktop.status = "connected"
        with self.assertRaises(HTTPException):
            await desktop.activate()
        desktop.page.goto.assert_not_awaited()
        desktop.status = "active"
        desktop.created = time.monotonic() - 3601
        desktop.deadline = time.monotonic() + 10
        self.assertFalse(desktop.input_enabled())

    async def test_sweep_starts_all_expired_cleanup_concurrently(self):
        started = [asyncio.Event(), asyncio.Event()]
        release = asyncio.Event()
        items = []
        for index in range(2):
            desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(), target_url="https://console.test/"))
            desktop.deadline = time.monotonic() - 1
            async def stop(_reason, index=index):
                started[index].set()
                await release.wait()
            desktop.stop = stop
            items.append(desktop)
        with patch.dict(w.desktops, {item.id: item for item in items}, clear=True):
            task = asyncio.create_task(w.sweep())
            try:
                await asyncio.wait_for(asyncio.gather(*(event.wait() for event in started)), 1)
            finally:
                release.set()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
