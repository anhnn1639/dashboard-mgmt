import importlib.util
import io
import unittest
from pathlib import Path
from unittest.mock import Mock
from urllib.error import HTTPError


spec = importlib.util.spec_from_file_location("verify_api_routes", Path(__file__).resolve().parents[2] / "deploy" / "verify-api-routes.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class DeploymentRouteTests(unittest.TestCase):
    def test_accepts_only_live_protected_routes(self):
        opener = Mock()
        opener.open.side_effect = [HTTPError("http://127.0.0.1", 401, "Unauthorized", {}, io.BytesIO(b'{"detail":"Authentication required"}')) for _ in probe.REQUIRED_ROUTES]
        probe.verify_routes(opener, deadline_seconds=0)
        self.assertEqual(opener.open.call_count, len(probe.REQUIRED_ROUTES))
        for call in opener.open.call_args_list:
            request = call.args[0]
            self.assertTrue(request.full_url.startswith("http://127.0.0.1:8000/api/v1/"))
            self.assertFalse(request.has_header("Authorization"))
            self.assertEqual(request.get_method(), "GET")

    def test_fails_on_old_api_or_unprotected_endpoint(self):
        for status in (404, 200, 403, 503):
            opener = Mock()
            opener.open.side_effect = HTTPError("http://127.0.0.1", status, "test", {}, io.BytesIO(b'{"detail":"test"}'))
            with self.assertRaisesRegex(RuntimeError, f"got {status}"):
                probe.verify_routes(opener, deadline_seconds=0)

    def test_rejects_non_api_auth_response(self):
        opener = Mock()
        opener.open.side_effect = HTTPError("http://127.0.0.1", 401, "test", {}, io.BytesIO(b'{}'))
        with self.assertRaisesRegex(RuntimeError, "not an API"):
            probe.verify_routes(opener, deadline_seconds=0)
