import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.error import HTTPError

from app.web_sessions import BlockedOriginReporter, WebSessionError, WebSessionHub


class WebHubTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_activation_without_recording_and_no_lease_after_loss(self):
        hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recording"
            activate, closed = AsyncMock(), AsyncMock()
            gets = 0

            async def call(method, url, payload=None):
                nonlocal gets
                if method == "GET":
                    gets += 1
                    if gets == 1:
                        activate.assert_not_awaited()
                    elif gets == 2:
                        activate.assert_not_awaited()
                        path.write_bytes(b"recorded-frame")
                    elif gets == 3:
                        activate.assert_awaited_once()
                        path.unlink()
                    return {"status": "connected" if gets < 3 else "active"}
                return {}

            hub.call = AsyncMock(side_effect=call)
            with patch("app.web_sessions.asyncio.sleep", new_callable=AsyncMock):
                await hub._watch("session", lambda: path if path.exists() else None, lambda: True, activate, closed)
            closed.assert_awaited_once_with("session", "web-recording-stopped")
            self.assertFalse(any(c.args[1].endswith("/lease") for c in hub.call.call_args_list))
            self.assertEqual(hub.call.call_args.args, ("DELETE", "/sessions/session"))

    async def test_revocation_closes_before_worker_activation(self):
        hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
        hub.call = AsyncMock(return_value={})
        activate, closed = AsyncMock(), AsyncMock()
        await hub._watch("session", lambda: None, lambda: False, activate, closed)
        activate.assert_not_awaited()
        closed.assert_awaited_once_with("session", "web-access-revoked")
        hub.call.assert_awaited_once_with("DELETE", "/sessions/session")

    async def test_preparation_validates_capability_and_cleans_invalid_response(self):
        hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
        hub.call = AsyncMock(return_value={"port": 443, "password": "bad"})
        with self.assertRaises(WebSessionError):
            await hub.prepare("session", "https://console.example.test/ui", 800, 600)
        self.assertEqual(hub.call.call_args.args, ("DELETE", "/sessions/session"))

    async def test_failed_worker_reason_is_preserved_only_for_known_codes(self):
        for reported, expected in (("capture-failed", "web-capture-failed"),
                                   ("transport-failed", "web-transport-failed"),
                                   ("lease-expired", "web-lease-expired"),
                                   ("https://sso.test/?SAMLRequest=secret", "web-browser-failed")):
            with self.subTest(reported=reported):
                hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
                hub.call = AsyncMock(return_value={"status": "failed", "reason": reported})
                activate, closed = AsyncMock(), AsyncMock()
                await hub._watch("session", lambda: None, lambda: True, activate, closed)
                activate.assert_not_awaited()
                closed.assert_awaited_once_with("session", expected)
                self.assertEqual(hub.call.call_args.args, ("DELETE", "/sessions/session"))

    async def test_failures_report_stage_without_echoing_exception_contents(self):
        secret_error = RuntimeError("sso.test/?SAMLRequest=secret")
        for stage, expected in (("authorization", "web-authorization-failed"),
                                ("status", "web-status-unavailable"),
                                ("recording", "web-recording-unreadable"),
                                ("activation", "web-activation-failed"),
                                ("lease", "web-lease-failed")):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
                path = Path(directory) / "session.guac"
                path.write_bytes(b"recorded-frame")
                activate, closed = AsyncMock(), AsyncMock()

                def authorize():
                    if stage == "authorization":
                        raise secret_error
                    return True

                def recording():
                    if stage == "recording":
                        raise PermissionError("private mount")
                    return path

                async def call(method, url, payload=None):
                    if method == "GET" and stage == "status":
                        raise secret_error
                    if url.endswith("/lease"):
                        raise secret_error
                    return {"status": "connected"}

                hub.call = AsyncMock(side_effect=call)
                if stage == "activation":
                    activate.side_effect = secret_error
                with patch("app.web_sessions.asyncio.sleep", new_callable=AsyncMock):
                    await hub._watch("session", recording, authorize, activate, closed)
                closed.assert_awaited_once_with("session", expected)
                self.assertEqual(hub.call.call_args.args, ("DELETE", "/sessions/session"))
                if stage in {"authorization", "status", "recording"}:
                    activate.assert_not_awaited()

    async def test_recording_storage_failure_preserves_only_fixed_probe_codes(self):
        for error, expected in (("recording-root-missing", "web-recording-root-missing"),
                                ("recording-permission-denied", "web-recording-permission-denied"),
                                ("recording-root-unreadable", "web-recording-root-unreadable"),
                                ("recording-private-path", "web-recording-unreadable")):
            with self.subTest(error=error):
                hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
                hub.call = AsyncMock(return_value={"status": "connected"})
                activate, closed = AsyncMock(), AsyncMock()

                def recording():
                    raise WebSessionError(error)

                await hub._watch("session", recording, lambda: True, activate, closed)
                activate.assert_not_awaited()
                closed.assert_awaited_once_with("session", expected)
                self.assertFalse(any(c.args[1].endswith("/lease") for c in hub.call.call_args_list))

    async def test_access_revoked_during_activation_is_distinguished(self):
        hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
        hub.call = AsyncMock(return_value={"status": "connected"})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.guac"
            path.write_bytes(b"recorded-frame")
            activate = AsyncMock(side_effect=WebSessionError("access-revoked"))
            closed = AsyncMock()
            await hub._watch("session", lambda: path, lambda: True, activate, closed)
            closed.assert_awaited_once_with("session", "web-access-revoked")
            self.assertFalse(any(c.args[1].endswith("/lease") for c in hub.call.call_args_list))

    async def test_invalid_worker_state_cannot_activate_or_renew_access(self):
        hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
        hub.call = AsyncMock(return_value={"status": "unrecognized"})
        activate, closed = AsyncMock(), AsyncMock()
        await hub._watch("session", lambda: None, lambda: True, activate, closed)
        activate.assert_not_awaited()
        closed.assert_awaited_once_with("session", "web-status-invalid")
        self.assertFalse(any(c.args[1].endswith("/lease") for c in hub.call.call_args_list))

    async def test_prepare_keeps_registered_redirects_without_certificate_opt_in(self):
        hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
        hub.call = AsyncMock(return_value={"port": 5901, "password": "Abc12345"})
        await hub.prepare("session", "https://console.example.test/ui", 800, 600, allowed_origins=["https://sso.example.test:8443"])
        hub.call.assert_awaited_once_with("POST", "/sessions", {
            "session_id": "session", "target_url": "https://console.example.test/ui",
            "width": 800, "height": 600, "allowed_origins": ["https://sso.example.test:8443"],
        })

    async def test_discovery_accepts_only_stored_form_origins_from_the_worker(self):
        hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
        hub.call = AsyncMock(return_value={"navigation": ["https://sso.test:8443", "https://sso.test:8443"],
                                           "resources": ["https://cdn.test:443"], "blocked": [], "error": "timeout"})
        found = await hub.discover("https://console.test/ui")
        self.assertEqual(found, {"navigation": ["https://sso.test:8443"], "resources": ["https://cdn.test:443"],
                                 "blocked": [], "error": "timeout"})
        self.assertEqual(hub.call.call_args.args, ("POST", "/discover", {"target_url": "https://console.test/ui"}))
        for invalid in ({"navigation": ["https://sso.test:8443/websso?SAMLRequest=secret"], "resources": [], "blocked": [], "error": ""},
                        {"navigation": ["https://sso.test"], "resources": [], "blocked": [], "error": ""},
                        {"navigation": ["https://sso.test:99999"], "resources": [], "blocked": [], "error": ""},
                        {"navigation": ["https://sso.test:8443"] * 17, "resources": [], "blocked": [], "error": ""},
                        {"navigation": [], "resources": [], "blocked": [], "error": "unexpected"},
                        {"resources": [], "blocked": [], "error": ""}):
            with self.subTest(invalid=invalid):
                hub.call = AsyncMock(return_value=invalid)
                with self.assertRaises(WebSessionError):
                    await hub.discover("https://console.test/ui")

    async def test_blocked_origins_are_reported_once_per_session_and_capped(self):
        seen = []
        async def blocked(session_id, origins):
            seen.append((session_id, origins))
        reporter = BlockedOriginReporter("session", blocked)
        reporter.offer({"blocked_origins": ["https://sso.test:8443", "https://sso.test:8443/websso?SAMLRequest=secret", 7, "https://cdn.test:443"]})
        await asyncio.sleep(0)
        reporter.offer({"blocked_origins": ["https://sso.test:8443"]})
        reporter.offer({"blocked_origins": [f"https://host{index}.test:443" for index in range(20)]})
        reporter.offer({"blocked_origins": "https://string.test:443"})
        await reporter.close()
        self.assertEqual(seen[0], ("session", ["https://sso.test:8443", "https://cdn.test:443"]))
        self.assertEqual(len(seen), 2)
        self.assertEqual(len(seen[1][1]), 6)
        self.assertEqual(len(reporter.reported), 8)

    async def test_failed_report_retries_only_uncommitted_origins_without_overlap(self):
        entered, finish = asyncio.Event(), asyncio.Event()
        attempts = []
        async def blocked(identifier, origins):
            attempts.append(origins)
            if len(attempts) == 1:
                raise RuntimeError("commit failed")
            entered.set()
            await finish.wait()
        reporter = BlockedOriginReporter("session", blocked)
        with patch("app.web_sessions.BLOCKED_RETRY_SECONDS", .01):
            reporter.offer({"blocked_origins": ["https://sso.test:443"]})
            await asyncio.wait_for(entered.wait(), 1)
            self.assertEqual(reporter.reported, set())
            reporter.offer({"blocked_origins": ["https://sso.test:443"]})
            await asyncio.sleep(.02)
            self.assertEqual(len(attempts), 2)
            finish.set()
            await reporter.close()
        self.assertEqual(reporter.reported, {"https://sso.test:443"})
        self.assertFalse(reporter.pending)

    async def test_reporter_timeout_and_cancellation_leave_no_background_task(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel):
                entered = asyncio.Event()
                async def blocked(identifier, origins):
                    entered.set()
                    await asyncio.Event().wait()
                reporter = BlockedOriginReporter("session", blocked)
                reporter.offer({"blocked_origins": ["https://sso.test:443"]})
                await entered.wait()
                with patch("app.web_sessions.BLOCKED_DRAIN_SECONDS", .02):
                    closing = asyncio.create_task(reporter.close())
                    await asyncio.sleep(0)
                    if cancel:
                        closing.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await closing
                    else:
                        await closing
                self.assertTrue(reporter.task.done())
                self.assertFalse(reporter.reported)

    async def test_slow_advisory_report_does_not_delay_leases_or_remote_shutdown(self):
        hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
        entered, release = asyncio.Event(), asyncio.Event()
        leases = []
        async def blocked(identifier, origins):
            entered.set()
            await release.wait()
        async def call(method, url, payload=None):
            if url.endswith("/lease"):
                leases.append(url)
                if len(leases) == 2:
                    return {}
            if method == "DELETE":
                self.assertTrue(entered.is_set())
                self.assertFalse(release.is_set())
                release.set()
            return {"status": "closed" if len(leases) == 2 else "connected", "blocked_origins": ["https://sso.test:443"]}
        hub.call = AsyncMock(side_effect=call)
        original_sleep = asyncio.sleep
        async def fast_tick(_seconds):
            await original_sleep(0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.guac"
            path.write_bytes(b"recorded-frame")
            with patch("app.web_sessions.asyncio.sleep", side_effect=fast_tick):
                await asyncio.wait_for(hub._watch("session", lambda: path, AsyncMock(return_value=True), AsyncMock(), AsyncMock(), blocked), 1)
        self.assertEqual(len(leases), 2)

    async def test_async_authorization_denial_and_failure_never_activate(self):
        for authorize, expected in ((AsyncMock(return_value=False), "web-access-revoked"), (AsyncMock(side_effect=TimeoutError), "web-authorization-failed")):
            hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
            hub.call = AsyncMock(return_value={})
            activate, closed = AsyncMock(), AsyncMock()
            await hub._watch("session", lambda: None, authorize, activate, closed)
            activate.assert_not_awaited()
            closed.assert_awaited_once_with("session", expected)

    async def test_watcher_reports_blocked_origins_before_the_session_closes(self):
        hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
        hub.call = AsyncMock(return_value={"status": "failed", "reason": "lease-expired",
                                           "blocked_origins": ["https://sso.test:8443"]})
        blocked, activate, closed = AsyncMock(), AsyncMock(), AsyncMock()
        await hub._watch("session", lambda: None, lambda: True, activate, closed, blocked)
        blocked.assert_awaited_once_with("session", ["https://sso.test:8443"])
        closed.assert_awaited_once_with("session", "web-lease-expired")
        activate.assert_not_awaited()

    async def test_worker_conflict_is_reported_as_busy_not_unavailable(self):
        hub = WebSessionHub("http://web-console:8081", lambda: "a" * 32)
        for code, expected in ((409, "busy"), (500, "unavailable")):
            with self.subTest(code=code):
                error = HTTPError("http://web-console:8081/discover", code, "conflict", {}, None)
                with patch("app.web_sessions.build_opener", side_effect=error), self.assertRaises(WebSessionError) as raised:
                    await hub.call("POST", "/discover", {"target_url": "https://console.test/ui"})
                self.assertEqual(str(raised.exception), expected)

    async def test_missing_service_fails_without_network(self):
        hub = WebSessionHub("", lambda: "a" * 32)
        with self.assertRaises(WebSessionError):
            await hub.call("POST", "/sessions")
