"""Bounded recovery must deliver fresh browser pixels before login can proceed."""
import asyncio
import base64
import io
import os
import time
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from playwright.async_api import async_playwright

from auto_login import LoginCredentials, SavedAccountLogin
import browser_worker as w


class FrameWriter:
    def __init__(self, on_drain=None):
        self.writes = []
        self.closed = False
        self.drained = asyncio.Event()
        self.on_drain = on_drain

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        if self.on_drain:
            await self.on_drain()
        self.drained.set()

    def close(self):
        self.closed = True


class CaptureRecoveryTests(unittest.IsolatedAsyncioTestCase):
    def desktop(self):
        desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(),
            target_url="https://console.test/login", width=800, height=600))
        desktop.status = "active"
        desktop.deadline = time.monotonic() + 120
        desktop.page = SimpleNamespace(url=desktop.url, main_frame=object(),
            keyboard=SimpleNamespace(down=AsyncMock(), up=AsyncMock()),
            mouse=SimpleNamespace(move=AsyncMock(), up=AsyncMock()))
        desktop.login = SavedAccountLogin(desktop,
            LoginCredentials(username="fixture-user", password="fixture-password"))
        desktop.frame_requested.set()
        return desktop

    def surface(self):
        buffer = io.BytesIO()
        w.Image.new("RGB", (800, 572), "#29a463").save(buffer, format="PNG")
        return {"data": base64.b64encode(buffer.getvalue()).decode("ascii")}

    async def stop_frame_task(self, task):
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def test_one_timeout_recovers_only_with_fresh_pixels_and_drained_transport(self):
        desktop, writer = self.desktop(), FrameWriter()
        attempts = 0

        async def capture(_method, _params):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise TimeoutError()
            self.assertTrue(desktop.capture_recovering)
            self.assertFalse(desktop.automation_enabled())
            self.assertFalse(desktop.interaction_enabled())
            self.assertFalse(writer.writes, "No clock-only or stale frame may mask recovery")
            await desktop.key(ord("a"), False)
            await desktop.mouse(0, 80, 80)
            desktop.page.keyboard.up.assert_not_awaited()
            desktop.page.mouse.move.assert_not_awaited()
            return self.surface()

        async def before_drain():
            self.assertFalse(desktop.automation_enabled())

        writer.on_drain = before_drain
        desktop.capture = SimpleNamespace(send=AsyncMock(side_effect=capture))
        task = asyncio.create_task(desktop.frames(writer))
        try:
            await asyncio.wait_for(writer.drained.wait(), 2)
            self.assertEqual(attempts, 2)
            self.assertEqual(len(writer.writes), 1)
            # Actual browser image begins at row 28, in VNC BGRX format.
            offset = 16 + 28 * 800 * 4
            self.assertEqual(writer.writes[0][offset:offset + 4], bytes((0x63, 0xa4, 0x29, 0)))
            self.assertFalse(writer.closed)
            self.assertEqual(desktop.reason, "")
            self.assertFalse(desktop.capture_recovering)
            self.assertTrue(desktop.website_frame_ready)
            self.assertTrue(desktop.automation_enabled())
        finally:
            await self.stop_frame_task(task)
            desktop.login.cancel()

    async def test_recovery_releases_held_input_before_reopening_interaction(self):
        desktop, writer = self.desktop(), FrameWriter()
        desktop.keys.add('Control')
        desktop.buttons = 1
        attempts = 0
        async def capture(_method, _params):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise TimeoutError()
            await desktop.key(0xffe3, False)
            await desktop.mouse(0, 80, 80)
            desktop.page.keyboard.up.assert_not_awaited()
            desktop.page.mouse.up.assert_not_awaited()
            return self.surface()
        async def release_key(key):
            self.assertTrue(writer.drained.is_set())
            self.assertFalse(desktop.interaction_enabled())
            self.assertEqual(key, 'Control')
        desktop.page.keyboard.up.side_effect = release_key
        desktop.capture = SimpleNamespace(send=AsyncMock(side_effect=capture))
        task = asyncio.create_task(desktop.frames(writer))
        try:
            async with asyncio.timeout(2):
                while not desktop.website_frame_ready:
                    await asyncio.sleep(.01)
            desktop.page.keyboard.up.assert_awaited_once_with('Control')
            desktop.page.mouse.up.assert_awaited_once_with(button='left')
            self.assertEqual(desktop.keys, set())
            self.assertEqual(desktop.buttons, 0)
            self.assertTrue(desktop.interaction_enabled())
            self.assertFalse(writer.closed)
        finally:
            await self.stop_frame_task(task)
            desktop.login.cancel()

    async def test_action_rechecks_capture_gate_after_waiting_for_renderer(self):
        desktop = self.desktop()
        desktop.website_frame_ready = True
        frame = SimpleNamespace(url=desktop.url)
        evaluating, proceed = asyncio.Event(), asyncio.Event()
        async def evaluate(_expression):
            evaluating.set()
            await proceed.wait()
            return desktop.url
        button = SimpleNamespace(evaluate=AsyncMock(side_effect=evaluate))
        task = asyncio.create_task(desktop.login.valid_action(frame, button))
        try:
            await asyncio.wait_for(evaluating.wait(), 1)
            desktop.capture_recovering = True
            proceed.set()
            self.assertFalse(await asyncio.wait_for(task, 1))
        finally:
            await self.stop_frame_task(task)
            desktop.login.cancel()

    async def test_permanent_capture_hang_is_bounded_closes_and_clears_credentials(self):
        desktop, writer = self.desktop(), FrameWriter()
        cancelled = 0

        async def never_returns(_method, _params):
            nonlocal cancelled
            try:
                await asyncio.Event().wait()
            finally:
                cancelled += 1

        desktop.capture = SimpleNamespace(send=AsyncMock(side_effect=never_returns))
        started = time.monotonic()
        with patch.object(w, "CAPTURE_ATTEMPT_SECONDS", .04), patch.object(w, "CAPTURE_RECOVERY_SECONDS", .1):
            await asyncio.wait_for(desktop.frames(writer), 1)
        self.assertLess(time.monotonic() - started, .5)
        self.assertEqual(desktop.capture.send.await_count, 2)
        self.assertEqual(cancelled, 2)
        self.assertFalse(writer.writes)
        self.assertTrue(writer.closed)
        self.assertEqual(desktop.reason, "capture-failed")
        self.assertFalse(desktop.automation_enabled())
        self.assertEqual((desktop.login.username, desktop.login.password), ("", ""))

    async def test_lease_expiring_between_attempts_blocks_second_capture_and_input(self):
        desktop, writer = self.desktop(), FrameWriter()

        async def expires(_method, _params):
            desktop.deadline = time.monotonic() - 1
            raise TimeoutError()

        desktop.capture = SimpleNamespace(send=AsyncMock(side_effect=expires))
        await asyncio.wait_for(desktop.frames(writer), 1)
        desktop.capture.send.assert_awaited_once()
        await desktop.key(ord("a"), True)
        await desktop.mouse(1, 80, 80)
        desktop.page.keyboard.down.assert_not_awaited()
        desktop.page.mouse.move.assert_not_awaited()
        self.assertFalse(writer.writes)
        self.assertTrue(writer.closed)
        self.assertFalse(desktop.automation_enabled())
        self.assertEqual((desktop.login.username, desktop.login.password), ("", ""))

    async def test_navigation_during_drain_requires_a_frame_of_the_new_document(self):
        desktop = self.desktop()
        desktop.capture = SimpleNamespace(send=AsyncMock(return_value=self.surface()))

        async def navigate_during_drain():
            # A same-URL reload also changes the document, so URL equality alone
            # cannot establish that the visible form has already been recorded.
            desktop.frame_navigated(desktop.page.main_frame)

        writer = FrameWriter(navigate_during_drain)
        task = asyncio.create_task(desktop.frames(writer))
        try:
            await asyncio.wait_for(writer.drained.wait(), 2)
            self.assertEqual(len(writer.writes), 1)
            self.assertFalse(writer.closed)
            self.assertFalse(desktop.website_frame_ready)
            self.assertFalse(desktop.automation_enabled())
        finally:
            await self.stop_frame_task(task)
            desktop.login.cancel()

    async def test_activation_during_placeholder_drain_does_not_release_login(self):
        desktop = self.desktop()
        desktop.status = "connected"
        desktop.capture = SimpleNamespace(send=AsyncMock(return_value=self.surface()))

        async def activate_during_drain():
            desktop.status = "active"

        writer = FrameWriter(activate_during_drain)
        task = asyncio.create_task(desktop.frames(writer))
        try:
            await asyncio.wait_for(writer.drained.wait(), 2)
            desktop.capture.send.assert_not_awaited()
            self.assertEqual(len(writer.writes), 1)
            self.assertFalse(writer.closed)
            self.assertFalse(desktop.website_frame_ready)
            self.assertFalse(desktop.automation_enabled())
            self.assertEqual(desktop.reason, "")
        finally:
            await self.stop_frame_task(task)
            desktop.login.cancel()


@unittest.skipUnless(os.environ.get("TRAM_TEST_BROWSER"), "Real browser fixture runs in Web Console CI")
class BusyRendererTests(unittest.IsolatedAsyncioTestCase):
    async def test_six_second_busy_renderer_recovers_a_fresh_surface_within_recording_deadline(self):
        pw = await async_playwright().start()
        executable = os.environ["TRAM_TEST_BROWSER"]
        browser = await pw.chromium.launch(headless=True, chromium_sandbox=True,
            executable_path=None if executable == "chromium" else executable)
        busy_task = None
        try:
            context = await browser.new_context(viewport={"width": 800, "height": 572})
            # The entire website and credentials are local test fixtures; no
            # production page, account or network service is used.
            await context.route("**/*", lambda route: route.fulfill(content_type="text/html",
                body="<html><body style='margin:0;background:#112233'></body></html>"))
            page = await context.new_page()
            await page.goto("https://console.test/login")
            desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(),
                target_url=page.url, width=800, height=600))
            desktop.page = page
            desktop.status = "active"
            desktop.deadline = time.monotonic() + 30
            desktop.capture = await context.new_cdp_session(page)
            await desktop.capture_surface()
            started = asyncio.Event()
            page.on("console", lambda message: started.set() if message.text == "fixture-busy" else None)
            busy_task = asyncio.create_task(page.evaluate("""() => {
                console.log('fixture-busy');
                const until = performance.now() + 6000;
                while (performance.now() < until) {}
                document.body.style.background = '#29a463';
            }"""))
            await asyncio.wait_for(started.wait(), 2)
            before = time.monotonic()
            surface = await desktop.capture_surface()
            elapsed = time.monotonic() - before
            await asyncio.wait_for(busy_task, 2)
            with w.Image.open(io.BytesIO(base64.b64decode(surface["data"]))) as image:
                self.assertEqual(image.convert("RGB").getpixel((100, 100)), (0x29, 0xa4, 0x63))
            self.assertLess(elapsed, w.CAPTURE_RECOVERY_SECONDS)
            self.assertTrue(desktop.capture_recovering, "The fixture must reproduce the original four-second timeout")
            self.assertFalse(desktop.automation_enabled(), "Only delivery through frames may mark capture ready")
        finally:
            if busy_task:
                busy_task.cancel()
                await asyncio.gather(busy_task, return_exceptions=True)
            await browser.close()
            await pw.stop()
