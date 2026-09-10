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

    async def test_missing_service_fails_without_network(self):
        hub = WebSessionHub("", lambda: "a" * 32)
        with self.assertRaises(WebSessionError):
            await hub.call("POST", "/sessions")
