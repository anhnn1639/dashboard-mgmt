import importlib.util
import base64
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "tram_agent.py"
SPEC = importlib.util.spec_from_file_location("tram_agent", MODULE_PATH)
assert SPEC and SPEC.loader
tram_agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tram_agent)


class AgentSecurityTests(unittest.TestCase):
    def test_tunnel_url_requires_https(self):
        with tempfile.TemporaryDirectory() as directory:
            secure = tram_agent.Config(str(Path(directory) / "agent.json"))
            secure.agent_endpoint = "https://ops.example.com:9443/api/v1/agent"
            self.assertEqual(
                tram_agent.tunnel_url(secure, "control?agent_id=test"),
                "wss://ops.example.com:9443/api/v1/agent/tunnel/control?agent_id=test",
            )
            secure.agent_endpoint = "http://ops.example.com/api/v1/agent"
            with self.assertRaisesRegex(RuntimeError, "HTTPS"):
                tram_agent.tunnel_url(secure, "control")

    def test_file_delivery_rejects_traversal_before_network_access(self):
        with tempfile.TemporaryDirectory() as directory:
            config = tram_agent.Config(str(Path(directory) / "agent.json"))
            result, message = tram_agent.deliver_file(
                config,
                {
                    "transfer_id": "89d17447-bbd7-4f3c-a9a8-6796c9348b1a",
                    "filename": "../payload.exe",
                    "sha256": "a" * 64,
                    "size_bytes": 10,
                },
                {"os_family": "linux"},
            )
            self.assertEqual(result, 2)
            self.assertIn("Unsafe", message)

    def test_agent_never_accepts_arbitrary_tunnel_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            config = tram_agent.Config(str(Path(directory) / "agent.json"))
            # Invalid instructions return before creating a local socket.
            tram_agent.tunnel_stream_worker(
                config,
                {
                    "session_id": "89d17447-bbd7-4f3c-a9a8-6796c9348b1a",
                    "protocol": "ssh",
                    "port": 445,
                },
            )
            tram_agent.tunnel_stream_worker(config, {"session_id": "not-a-uuid", "protocol": "ssh", "port": "not-a-port"})

    def test_file_delivery_rejects_windows_device_names(self):
        with tempfile.TemporaryDirectory() as directory:
            config = tram_agent.Config(str(Path(directory) / "agent.json"))
            result, message = tram_agent.deliver_file(
                config,
                {
                    "transfer_id": "89d17447-bbd7-4f3c-a9a8-6796c9348b1a",
                    "filename": "CON.txt",
                    "sha256": "a" * 64,
                    "size_bytes": 10,
                },
                {"os_family": "windows"},
            )
            self.assertEqual(result, 2)
            self.assertIn("Unsafe", message)

    def test_windows_msi_filename_carries_origin_and_ca_pin(self):
        netloc = base64.urlsafe_b64encode(b"ops.company.example").decode().rstrip("=")
        package_id = "89d17447-bbd7-4f3c-a9a8-6796c9348b1a"
        package_secret = "a" * 43
        ca_fingerprint = "b" * 64
        source = f"C:/Downloads/TramAgent--{netloc}--{package_id}--{package_secret}--{ca_fingerprint}.msi"
        self.assertEqual(
            tram_agent.parse_windows_installer_source(source),
            ("https://ops.company.example", package_id, package_secret, ca_fingerprint),
        )
        with self.assertRaisesRegex(RuntimeError, "bootstrap"):
            tram_agent.parse_windows_installer_source("C:/Downloads/renamed.msi")


if __name__ == "__main__":
    unittest.main()
