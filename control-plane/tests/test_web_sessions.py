import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app.web_sessions import WebSessionError, WebSessionHub


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

    async def test_missing_service_fails_without_network(self):
        hub = WebSessionHub("", lambda: "a" * 32)
        with self.assertRaises(WebSessionError):
            await hub.call("POST", "/sessions")
