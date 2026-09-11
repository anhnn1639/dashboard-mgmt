import asyncio
import base64
import io
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

    def test_automatic_certificate_handling_keeps_destination_boundary(self):
        for legacy in (None, False, True):
            options = {} if legacy is None else {"ignore_https_errors": legacy}
            desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(), target_url="https://console.test/", **options))
            self.assertTrue(desktop.ignore_https_errors)
            self.assertTrue(desktop.permitted("https://console.test/websso"))
            self.assertFalse(desktop.permitted("https://unlisted.test/"))
            self.assertFalse(desktop.permitted("https://console.test:8443/"))

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

    async def test_configured_redirects_only_resolve_once_and_never_admit_script_origins(self):
        desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(), target_url="https://console.test/ui", allowed_origins=["https://sso.test:8443", "http://old.test:80"]))
        desktop.status = "active"
        self.assertTrue(desktop.permitted("https://sso.test:8443/websso/SAML2/SSO?value=hidden"))
        self.assertTrue(desktop.permitted("ws://old.test/socket"))
        self.assertFalse(desktop.permitted("https://sso.test:443/"))
        with patch.object(w, "pinned_address", new_callable=AsyncMock, return_value="10.80.9.9") as resolve:
            self.assertIsNone(await desktop.resolve_destination("https", "outside.test", 443))
            resolve.assert_not_awaited()
            self.assertEqual(await desktop.resolve_destination("https", "sso.test", 8443), "10.80.9.9")
            self.assertEqual(await desktop.resolve_destination("https", "sso.test", 8443), "10.80.9.9")
            resolve.assert_awaited_once()
        with patch.object(w, "pinned_address", new_callable=AsyncMock, side_effect=ValueError("unsafe target")):
            self.assertIsNone(await desktop.resolve_destination("http", "old.test", 80))
        desktop.deadline = time.monotonic() - 1
        self.assertIsNone(await desktop.resolve_destination("https", "sso.test", 8443))

    async def test_blocked_navigations_become_suggestions_without_paths_or_tokens(self):
        desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(), target_url="https://console.test/ui", allowed_origins=["https://sso.test:8443"]))
        desktop.status = "active"

        def request(url, navigation=True):
            return type("Request", (), {"url": url, "is_navigation_request": staticmethod(lambda: navigation)})()

        desktop.observe_request(request("https://console.test/websso/SAML2/SSO?SAMLRequest=PRIVATE"))
        desktop.observe_request(request("https://sso.test:8443/websso"))
        # Page scripts must not be able to propose origins, only navigations.
        desktop.observe_request(request("https://tracker.test/pixel", False))
        desktop.observe_request(request("https://sso-new.test:8443/login?SAMLRequest=PRIVATE"))
        desktop.observe_request(request("https://sso-new.test:8443/retry"))
        self.assertEqual(desktop.blocked_origins, ["https://sso-new.test:8443"])
        self.assertIn("https://sso-new.test:8443", desktop.notice)
        self.assertNotIn("PRIVATE", desktop.notice)
        for index in range(12):
            desktop.observe_request(request(f"https://extra{index}.test/"))
        self.assertEqual(len(desktop.blocked_origins), 8)

    async def test_navigation_errors_do_not_expose_saml_tokens(self):
        desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(), target_url="https://console.test/"))
        desktop.page = type("Page", (), {"goto": AsyncMock(side_effect=RuntimeError("net::ERR_CERT_AUTHORITY_INVALID https://console.test/?SAMLRequest=PRIVATE"))})()
        await desktop.navigate()
        self.assertEqual(desktop.navigation_error, "certificate")
        self.assertNotIn("PRIVATE", desktop.notice)
        self.assertIn("chứng thư", desktop.notice)
        desktop.page.goto.side_effect = w.BrowserTimeoutError("private-url")
        await desktop.navigate()
        self.assertEqual(desktop.navigation_error, "timeout")

    async def test_discovery_reports_origins_only_and_separates_unreachable_ones(self):
        probe = w.Discovery("https://console.test/ui")
        probe.destinations.update({("https", "sso.test", 8443): "10.80.9.9", ("https", "cdn.test", 443): "10.80.9.10",
                                   ("https", "broken.test", 443): None})
        probe.observe("https://console.test/websso/SAML2/SSO?SAMLRequest=PRIVATE", True)
        probe.observe("https://sso.test:8443/websso?SAMLRequest=PRIVATE", True)
        probe.observe("https://sso.test:8443/theme.css", False)
        probe.observe("https://cdn.test/app.js", False)
        probe.observe("https://broken.test/logo.png", False)
        probe.observe("data:text/html,ignored", False)
        result = probe.result()
        self.assertEqual(result, {"navigation": ["https://sso.test:8443"], "resources": ["https://cdn.test:443"],
                                  "blocked": ["https://broken.test:443"], "error": ""})
        self.assertNotIn("PRIVATE", str(result))

    async def test_discovery_promotes_a_resource_origin_the_site_navigates_to(self):
        probe = w.Discovery("https://console.test/ui")
        probe.destinations[("https", "sso.test", 443)] = "10.80.9.9"
        probe.observe("https://sso.test/theme.css", False)
        probe.observe("https://sso.test/login", True)
        self.assertEqual(probe.result()["navigation"], ["https://sso.test:443"])
        self.assertEqual(probe.result()["resources"], [])

    async def test_discovery_resolves_once_and_keeps_the_unicast_address_check(self):
        probe = w.Discovery("https://console.test/ui")
        with patch.object(w, "pinned_address", new_callable=AsyncMock, return_value="10.80.9.9") as resolve:
            self.assertEqual(await probe.resolve_destination("https", "sso.test", 8443), "10.80.9.9")
            self.assertEqual(await probe.resolve_destination("https", "sso.test", 8443), "10.80.9.9")
            resolve.assert_awaited_once()
        with patch.object(w, "pinned_address", new_callable=AsyncMock, side_effect=ValueError("unsafe target")):
            self.assertIsNone(await probe.resolve_destination("https", "metadata.test", 80))
        probe.active = False
        self.assertIsNone(await probe.resolve_destination("https", "sso.test", 8443))

    async def test_discovery_endpoint_requires_the_secret_and_refuses_parallel_probes(self):
        client = TestClient(w.app)
        with patch.dict(w.os.environ, {"GUACAMOLE_JSON_SECRET": "a" * 32}):
            self.assertEqual(client.post("/discover", json={"target_url": "https://console.test/"}).status_code, 401)
            headers = {"Authorization": "Bearer " + hashlib.sha256(("tram-web-console:" + "a" * 32).encode()).hexdigest()}
            invalid = client.post("/discover", headers=headers, json={"target_url": "https://user:private-test-value@console.test/"})
            self.assertEqual(invalid.status_code, 422)
            self.assertNotIn("private-test-value", invalid.text)
            await w.discovery_lock.acquire()
            try:
                self.assertEqual(client.post("/discover", headers=headers, json={"target_url": "https://console.test/"}).status_code, 409)
            finally:
                w.discovery_lock.release()

    async def test_session_status_reports_blocked_origins_for_the_api(self):
        desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(), target_url="https://console.test/ui"))
        desktop.blocked_origins.append("https://sso-new.test:8443")
        with patch.dict(w.os.environ, {"GUACAMOLE_JSON_SECRET": "a" * 32}), patch.dict(w.desktops, {desktop.id: desktop}):
            headers = {"Authorization": "Bearer " + hashlib.sha256(("tram-web-console:" + "a" * 32).encode()).hexdigest()}
            state = TestClient(w.app).get("/sessions/" + desktop.id, headers=headers).json()
        self.assertEqual(state["blocked_origins"], ["https://sso-new.test:8443"])

    async def test_recording_captures_surface_without_waiting_for_web_fonts(self):
        desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(), target_url="https://console.test/", width=800, height=600))
        png = io.BytesIO()
        w.Image.new("RGB", (800, 572), "#abcdef").save(png, format="PNG")
        desktop.capture = type("Capture", (), {"send": AsyncMock(return_value={"data": base64.b64encode(png.getvalue()).decode()})})()
        desktop.page = type("Page", (), {"screenshot": AsyncMock(side_effect=AssertionError("Must not wait for fonts"))})()
        written = []
        class Writer:
            def write(self, data):
                written.append(data)
                desktop.status = "closed"
            async def drain(self):
                pass
            def close(self):
                raise AssertionError("Healthy surface capture must not close the transport")
        desktop.status = "active"
        desktop.frame_requested.set()
        await asyncio.wait_for(desktop.frames(Writer()), 2)
        desktop.page.screenshot.assert_not_awaited()
        self.assertEqual(desktop.capture.send.call_args.args[0], "Page.captureScreenshot")
        self.assertEqual(len(written), 1)
        self.assertEqual(len(written[0]), 16 + 800 * 600 * 4)
        # Row28 is the first website pixel, encoded as default RFB BGRX.
        self.assertEqual(written[0][16 + 28 * 800 * 4:16 + 28 * 800 * 4 + 4], bytes([0xef, 0xcd, 0xab, 0]))

    async def test_discovery_caps_combined_blocked_results_and_marks_unresolved(self):
        probe = w.Discovery("https://console.test/ui")
        for index in range(16):
            probe.observe(f"https://nav{index}.test/login", True)
            probe.observe(f"https://resource{index}.test/app.js", False)
            probe.destinations[("https", f"nav{index}.test", 443)] = None
        result = probe.result()
        self.assertEqual(len(result["blocked"]), 16)
        self.assertEqual(result["navigation"], [])
        self.assertEqual(result["resources"], [])

    async def test_discovery_tracks_pending_requests_without_saving_urls(self):
        probe = w.Discovery("https://console.test/ui")
        request = type("Request", (), {"url": "https://console.test/boot?secret=private", "is_navigation_request": lambda self: False})()
        probe.request_started(request)
        self.assertIn(request, probe.pending_requests)
        probe.request_finished(request)
        self.assertFalse(probe.pending_requests)
        self.assertNotIn("private", str(probe.result()))
