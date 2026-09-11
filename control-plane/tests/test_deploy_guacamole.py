"""Deployment checks use an empty identity and never initiate remote access."""
import base64
import hashlib
import hmac
import importlib.util
import io
import json
import socket
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from email.message import Message
from urllib.error import HTTPError
from urllib.parse import parse_qs

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

spec = importlib.util.spec_from_file_location("verify_guacamole", Path(__file__).resolve().parents[2] / "deploy/verify-guacamole.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
KEY = "0123456789abcdef0123456789abcdef"


class GuacamoleDeploymentTests(unittest.TestCase):
    def test_authenticates_only_empty_short_lived_identity_then_releases_it(self):
        opener = Mock()
        opener.open.side_effect = [io.BytesIO(b'{"authToken":"fixture-token","dataSource":"json"}'), io.BytesIO(b"")]
        before = int(time.time() * 1000)
        probe.verify_authentication(opener, KEY)
        request = opener.open.call_args_list[0].args[0]
        encrypted = base64.b64decode(parse_qs(request.data.decode())["data"][0])
        decryptor = Cipher(algorithms.AES(bytes.fromhex(KEY)), modes.CBC(bytes(16))).decryptor()
        padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        signed = unpadder.update(padded) + unpadder.finalize()
        self.assertEqual(signed[:32], hmac.new(bytes.fromhex(KEY), signed[32:], hashlib.sha256).digest())
        identity = json.loads(signed[32:])
        self.assertEqual(identity["connections"], {})
        self.assertEqual(set(identity), {"connections", "username", "expires"})
        self.assertTrue(identity["username"].startswith("deployment-check-"))
        self.assertGreaterEqual(identity["expires"], before + 29000)
        self.assertLess(identity["expires"], before + 32000)
        cleanup = opener.open.call_args_list[1].args[0]
        self.assertEqual(cleanup.get_method(), "DELETE")
        self.assertTrue(cleanup.full_url.endswith("/api/tokens/fixture-token"))

    def test_auth_failures_do_not_disclose_secret_or_response(self):
        for failure in (HTTPError("http://fixture/?token=PRIVATE", 403, "PRIVATE", {}, io.BytesIO(b"PRIVATE")),
                        OSError("PRIVATE"), ValueError("PRIVATE")):
            with self.subTest(kind=type(failure).__name__):
                opener = Mock()
                opener.open.side_effect = failure
                with self.assertRaises(RuntimeError) as caught:
                    probe.verify_authentication(opener, KEY, deadline_seconds=0)
                self.assertNotIn("PRIVATE", str(caught.exception))
                self.assertNotIn(KEY, str(caught.exception))

    def test_wrong_provider_releases_token_but_fails_check(self):
        opener = Mock()
        opener.open.side_effect = [io.BytesIO(b'{"authToken":"fixture-token","dataSource":"mysql"}'), io.BytesIO(b"")]
        with self.assertRaises(RuntimeError):
            probe.verify_authentication(opener, KEY)
        self.assertEqual(opener.open.call_args_list[1].args[0].get_method(), "DELETE")

    def test_missing_key_does_not_send_request(self):
        opener = Mock()
        with self.assertRaisesRegex(RuntimeError, "key"):
            probe.verify_authentication(opener, "")
        opener.open.assert_not_called()

    def protocol_exchange(self, protocol, reply):
        local, remote = socket.socketpair()
        received = []
        errors = []
        def server():
            try:
                with remote:
                    remote.settimeout(2)
                    received.append(probe.read_instruction(remote))
                    # Fragment across reads to exercise the actual stream parser.
                    for byte in reply:
                        remote.sendall(bytes([byte]))
                    received.append(remote.recv(1024))
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=server)
        thread.start()
        try:
            probe.verify_protocol(protocol, connect=lambda address, timeout: local)
        finally:
            local.close()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        return received

    def test_ssh_and_rdp_handshake_stop_before_remote_connect(self):
        for protocol in ("ssh", "rdp"):
            with self.subTest(protocol=protocol):
                received = self.protocol_exchange(protocol, b"4.args,13.VERSION_1_5_0,8.hostname,4.port,8.username,8.password;")
                self.assertEqual(received, [["select", protocol], b""])

    def test_unavailable_protocol_fails_without_remote_connection(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.recv.side_effect = [bytes([byte]) for byte in b"5.error,4.nope;"]
        with self.assertRaisesRegex(RuntimeError, "SSH handshake"):
            probe.verify_protocol("ssh", connect=lambda address, timeout: connection)
        connection.sendall.assert_called_once_with(b"6.select,3.ssh;")

    def test_malformed_and_unbounded_replies_fail_closed(self):
        for message in (b".", b"999999.", b"1.a!", b"4.args,"):
            connection = Mock()
            pending = io.BytesIO(message)
            connection.recv.side_effect = pending.read
            with self.subTest(message=message), self.assertRaises(ValueError):
                probe.read_instruction(connection)

    def test_waits_for_tomcat_but_never_retries_authentication_denial(self):
        opener = Mock()
        opener.open.side_effect = [
            HTTPError("http://fixture/", 503, "starting", {}, io.BytesIO()),
            io.BytesIO(b'{"authToken":"fixture-token","dataSource":"json"}'), io.BytesIO()]
        with patch.object(probe.time, "sleep"):
            probe.verify_authentication(opener, KEY)
        self.assertEqual(opener.open.call_count, 3)
        opener.open.reset_mock()
        opener.open.side_effect = HTTPError("http://fixture/", 403, "denied", {}, io.BytesIO())
        with self.assertRaisesRegex(RuntimeError, "403"):
            probe.verify_authentication(opener, KEY)
        opener.open.assert_called_once()

    def test_css_rejects_production_empty_wrong_mime_response(self):
        for mime, body, valid in (("application/octet-stream", b"", False),
                                  ("text/css", b"", False),
                                  ("text/css; charset=utf-8", b"/* fixture */", True)):
            with self.subTest(mime=mime, body=body):
                response = io.BytesIO(body)
                response.headers = Message()
                response.headers["Content-Type"] = mime
                opener = Mock()
                opener.open.return_value = response
                if valid:
                    probe.verify_stylesheet(opener)
                else:
                    with self.assertRaisesRegex(RuntimeError, "CSS"):
                        probe.verify_stylesheet(opener)
                self.assertEqual(opener.open.call_args.args[0], probe.BASE_URL + "/app.css")

    def test_slow_protocol_response_uses_one_total_deadline(self):
        connection = Mock()
        connection.recv.side_effect = [b"4"]
        with patch.object(probe.time, "monotonic", side_effect=[100, 100, 106]):
            with self.assertRaises(TimeoutError):
                probe.read_instruction(connection)
        connection.recv.assert_called_once()
