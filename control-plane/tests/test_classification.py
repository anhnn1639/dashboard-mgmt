import base64
import hashlib
import json
import os
import tempfile
import time
import unittest
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pyotp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

tmp = tempfile.TemporaryDirectory()
os.environ["DATABASE_URL"] = f"sqlite:///{Path(tmp.name) / 'test.db'}"
os.environ["JWT_SECRET"] = "test-secret-that-is-not-used-in-production"
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "test-only-password-123456"
os.environ["JOB_SECRET_KEY"] = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="

ca_key = ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Agent CA")])
ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(UTC) - timedelta(minutes=1)).not_valid_after(datetime.now(UTC) + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256()))
ca_cert_path = Path(tmp.name) / "agent-ca.crt"
ca_key_path = Path(tmp.name) / "agent-ca.key"
ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
ca_key_path.write_bytes(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
os.environ["AGENT_CA_CERT"] = str(ca_cert_path)
os.environ["AGENT_CA_KEY"] = str(ca_key_path)
os.environ["CADDY_ROOT_CA"] = str(ca_cert_path)

from app.main import Inventory, classify_os, guacamole_ssh_host_key  # noqa: E402
from app.main import app, engine  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def signed_agent_request(private_key: ec.EllipticCurvePrivateKey, certificate: x509.Certificate, path: str, payload: dict) -> tuple[bytes, dict[str, str]]:
    timestamp = str(int(time.time()))
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    message = f"{timestamp}\nPOST\n{path}\n{hashlib.sha256(body).hexdigest()}".encode()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return body, {
        "Content-Type": "application/json",
        "X-Tram-Agent-Certificate": base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode(),
        "X-Tram-Agent-Timestamp": timestamp,
        "X-Tram-Agent-Signature": base64.b64encode(signature).decode(),
    }


class ClassificationTests(unittest.TestCase):
    access_token = ""

    @classmethod
    def tearDownClass(cls):
        engine.dispose()

    @classmethod
    def login_admin(cls, client: TestClient) -> str:
        if cls.access_token:
            return cls.access_token
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "test-only-password-123456"})
        if login.status_code != 200:
            raise AssertionError(login.text)
        data = login.json()
        secret = parse_qs(urlsplit(data["provisioning_uri"]).query)["secret"][0]
        verified = client.post("/api/v1/auth/mfa/verify", json={"challenge_token": data["challenge_token"], "code": pyotp.TOTP(secret).now()})
        if verified.status_code != 200:
            raise AssertionError(verified.text)
        cls.access_token = verified.json()["access_token"]
        return cls.access_token

    def test_windows_is_classified_as_windows(self):
        family, verification = classify_os(Inventory(hostname="win-01", os_family="windows", os_name="Microsoft Windows Server 2025", distribution_id="windows"))
        self.assertEqual((family, verification), ("windows", "verified"))

    def test_ubuntu_is_classified_as_linux(self):
        family, verification = classify_os(Inventory(hostname="ub-01", os_family="linux", os_name="Ubuntu 24.04.3 LTS", distribution_id="ubuntu"))
        self.assertEqual((family, verification), ("linux", "verified"))

    def test_oracle_linux_is_classified_as_linux(self):
        family, verification = classify_os(Inventory(hostname="ol-01", os_family="linux", os_name="Oracle Linux Server 8.10", distribution_id="ol"))
        self.assertEqual((family, verification), ("linux", "verified"))

    def test_guacamole_host_key_is_a_known_hosts_entry(self):
        encoded_key = base64.b64encode(b"test-ed25519-host-key-material").decode()
        self.assertEqual(
            guacamole_ssh_host_key("10.20.1.11", f"ssh-ed25519 {encoded_key}"),
            f"10.20.1.11 ssh-ed25519 {encoded_key}",
        )
        self.assertEqual(
            guacamole_ssh_host_key("10.20.1.12", f"old-host ssh-ed25519 {encoded_key} comment"),
            f"10.20.1.12 ssh-ed25519 {encoded_key}",
        )

    def test_guacamole_rejects_invalid_host_key(self):
        with self.assertRaisesRegex(HTTPException, "SSH host key"):
            guacamole_ssh_host_key("10.20.1.11", "ssh-ed25519 not-base64!!!")

    def test_login_and_empty_fleet(self):
        with TestClient(app) as client:
            live = client.get("/livez")
            self.assertEqual(live.status_code, 200)
            self.assertEqual(live.json(), {"status": "ok"})
            setup = client.get("/api/v1/setup/status")
            self.assertEqual(setup.status_code, 200)
            self.assertTrue(setup.json()["setupRequired"])
            self.assertTrue(setup.json()["databaseConnected"])
            token = self.login_admin(client)
            fleet = client.get("/api/v1/servers", headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(fleet.status_code, 200)
            self.assertIsInstance(fleet.json()["items"], list)

    def test_windows_enrollment_is_automatically_categorized(self):
        with TestClient(app) as client:
            headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            token_response = client.post("/api/v1/enrollment-tokens", headers=headers, json={"label": "windows-test", "expected_os_family": "windows"})
            self.assertEqual(token_response.status_code, 201)

            agent_id = str(uuid.uuid4())
            agent_key = ec.generate_private_key(ec.SECP256R1())
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)])).sign(agent_key, hashes.SHA256())
            enroll = client.post("/api/v1/enroll", json={"token": token_response.json()["token"], "agent_id": agent_id, "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(), "inventory": {"hostname": "win-2025-01", "os_family": "windows", "os_name": "Microsoft Windows Server 2025 Datacenter", "os_version": "26100", "distribution_id": "windows", "architecture": "AMD64", "agent_version": "0.1.0", "addresses": ["10.30.1.50"]}})
            self.assertEqual(enroll.status_code, 201, enroll.text)
            self.assertEqual(enroll.json()["category"], "Windows")

            issued = x509.load_pem_x509_certificate(enroll.json()["certificate"].encode())
            checkin_payload = {"agent_id": agent_id, "agent_version": "0.1.0", "inventory": None, "metrics": {"cpu_percent": 12, "memory_percent": 40, "disk_percent": 30, "uptime_seconds": 3600, "pending_updates": 2, "services_running": 80, "alerts": 0}}
            checkin_body, checkin_headers = signed_agent_request(agent_key, issued, "/api/v1/agent/checkin", checkin_payload)
            checkin = client.post("/api/v1/agent/checkin", headers=checkin_headers, content=checkin_body)
            self.assertEqual(checkin.status_code, 200, checkin.text)

            rotation_token = client.post("/api/v1/enrollment-tokens", headers=headers, json={"label": "windows-rotation", "expected_os_family": "windows"})
            replacement_key = ec.generate_private_key(ec.SECP256R1())
            replacement_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)])).sign(replacement_key, hashes.SHA256())
            replacement = client.post("/api/v1/enroll", json={"token": rotation_token.json()["token"], "agent_id": agent_id, "csr_pem": replacement_csr.public_bytes(serialization.Encoding.PEM).decode(), "inventory": {"hostname": "win-2025-01", "os_family": "windows", "os_name": "Microsoft Windows Server 2025 Datacenter", "os_version": "26100", "distribution_id": "windows", "architecture": "AMD64", "agent_version": "0.1.0", "addresses": ["10.30.1.50"]}})
            self.assertEqual(replacement.status_code, 201, replacement.text)
            replacement_certificate = x509.load_pem_x509_certificate(replacement.json()["certificate"].encode())
            old_body, old_headers = signed_agent_request(agent_key, issued, "/api/v1/agent/checkin", checkin_payload)
            rejected_old_certificate = client.post("/api/v1/agent/checkin", headers=old_headers, content=old_body)
            self.assertEqual(rejected_old_certificate.status_code, 401)
            replacement_body, replacement_headers = signed_agent_request(replacement_key, replacement_certificate, "/api/v1/agent/checkin", checkin_payload)
            replacement_checkin = client.post("/api/v1/agent/checkin", headers=replacement_headers, content=replacement_body)
            self.assertEqual(replacement_checkin.status_code, 200, replacement_checkin.text)

            windows = client.get("/api/v1/servers?os_family=windows", headers=headers)
            self.assertTrue(any(item["id"] == agent_id and item["osFamily"] == "windows" for item in windows.json()["items"]))


if __name__ == "__main__":
    unittest.main()
