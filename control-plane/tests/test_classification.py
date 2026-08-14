import base64
import hashlib
import io
import json
import os
import tempfile
import tarfile
import time
import unittest
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

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
os.environ["AGENT_ASSETS_ROOT"] = str(Path(__file__).resolve().parents[2] / "agent")

from app.main import Inventory, SessionLocal, SystemSetting, classify_os, guacamole_ssh_host_key, settings  # noqa: E402
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

    def test_zero_touch_packages_pin_the_configured_domain_and_are_single_use(self):
        assert SessionLocal is not None
        with SessionLocal() as db:
            db.merge(SystemSetting(key="dashboard_url", value="https://ops.company.example"))
            db.commit()
        fake_msi = Path(tmp.name) / "TramVanHanhAgent.msi"
        fake_msi.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 8192)
        settings.windows_agent_msi = str(fake_msi)

        with TestClient(app) as client:
            headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            status = client.get("/api/v1/agent-packages/status", headers=headers)
            self.assertEqual(status.status_code, 200, status.text)
            self.assertEqual(status.json()["dashboardUrl"], "https://ops.company.example")
            self.assertTrue(status.json()["windowsMsiAvailable"])

            linux_package = client.post(
                "/api/v1/agent-packages",
                headers=headers,
                json={"label": "ubuntu-prod-01", "os_family": "linux", "expires_minutes": 15},
            )
            self.assertEqual(linux_package.status_code, 200, linux_package.text)
            self.assertIn("TramAgent-Linux-ubuntu-prod-01.run", linux_package.headers["content-disposition"])
            marker = b"__TRAM_AGENT_ARCHIVE__\n"
            archive_bytes = linux_package.content.split(marker, 1)[1]
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
                bootstrap = json.loads(archive.extractfile("bootstrap.json").read())
                self.assertEqual(bootstrap["server_url"], "https://ops.company.example")
                self.assertIn("BEGIN CERTIFICATE", bootstrap["server_ca_certificate"])

            linux_id = str(uuid.uuid4())
            linux_key = ec.generate_private_key(ec.SECP256R1())
            linux_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, linux_id)])).sign(linux_key, hashes.SHA256())
            linux_claim = {
                "package_id": bootstrap["package_id"],
                "package_secret": bootstrap["package_secret"],
                "agent_id": linux_id,
                "csr_pem": linux_csr.public_bytes(serialization.Encoding.PEM).decode(),
                "inventory": {"hostname": "ubuntu-prod-01", "os_family": "linux", "os_name": "Ubuntu 24.04", "os_version": "24.04", "distribution_id": "ubuntu", "architecture": "x86_64", "agent_version": "0.4.0", "addresses": ["10.40.1.10"]},
            }
            claimed = client.post("/api/v1/agent-bootstrap/claim", json=linux_claim)
            self.assertEqual(claimed.status_code, 201, claimed.text)
            self.assertEqual(claimed.json()["agent_endpoint"], "https://ops.company.example:9443/api/v1/agent")
            replay = client.post("/api/v1/agent-bootstrap/claim", json=linux_claim)
            self.assertEqual(replay.status_code, 401)

            windows_package = client.post(
                "/api/v1/agent-packages",
                headers=headers,
                json={"label": "win-prod-01", "os_family": "windows", "expires_minutes": 15},
            )
            self.assertEqual(windows_package.status_code, 200, windows_package.text)
            self.assertEqual(windows_package.content, fake_msi.read_bytes())
            filename = windows_package.headers["content-disposition"].split('filename="', 1)[1].rstrip('"')
            parts = filename[:-4].split("--")
            self.assertEqual(len(parts), 5)
            package_id, package_secret = parts[2], parts[3]

            mismatch_id = str(uuid.uuid4())
            mismatch_key = ec.generate_private_key(ec.SECP256R1())
            mismatch_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, mismatch_id)])).sign(mismatch_key, hashes.SHA256())
            mismatch = client.post("/api/v1/agent-bootstrap/claim", json={"package_id": package_id, "package_secret": package_secret, "agent_id": mismatch_id, "csr_pem": mismatch_csr.public_bytes(serialization.Encoding.PEM).decode(), "inventory": {"hostname": "wrong-linux", "os_family": "linux", "os_name": "Ubuntu 24.04", "distribution_id": "ubuntu", "agent_version": "0.4.0"}})
            self.assertEqual(mismatch.status_code, 400)

            windows_id = str(uuid.uuid4())
            windows_key = ec.generate_private_key(ec.SECP256R1())
            windows_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, windows_id)])).sign(windows_key, hashes.SHA256())
            windows_claim = client.post("/api/v1/agent-bootstrap/claim", json={"package_id": package_id, "package_secret": package_secret, "agent_id": windows_id, "csr_pem": windows_csr.public_bytes(serialization.Encoding.PEM).decode(), "inventory": {"hostname": "win-prod-01", "os_family": "windows", "os_name": "Microsoft Windows Server 2025", "distribution_id": "windows", "agent_version": "0.4.0"}})
            self.assertEqual(windows_claim.status_code, 201, windows_claim.text)

    def test_clean_file_is_encrypted_and_queued_for_four_eyes_approval(self):
        with TestClient(app) as client:
            headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            token_response = client.post("/api/v1/enrollment-tokens", headers=headers, json={"label": "file-test", "expected_os_family": "linux"})
            agent_id = str(uuid.uuid4())
            agent_key = ec.generate_private_key(ec.SECP256R1())
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)])).sign(agent_key, hashes.SHA256())
            enroll = client.post("/api/v1/enroll", json={"token": token_response.json()["token"], "agent_id": agent_id, "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(), "inventory": {"hostname": "ubuntu-file-test", "os_family": "linux", "os_name": "Ubuntu 24.04", "os_version": "24.04", "distribution_id": "ubuntu", "architecture": "x86_64", "agent_version": "0.3.0", "addresses": ["10.30.1.60"]}})
            self.assertEqual(enroll.status_code, 201, enroll.text)

            with patch("app.main.scan_with_clamav", return_value="stream: OK"):
                uploaded = client.post(
                    f"/api/v1/servers/{agent_id}/files",
                    headers=headers,
                    files={"file": ("approved-config.yaml", b"setting: approved\n", "application/yaml")},
                    data={"reason": "CHG-1234 approved configuration"},
                )
            self.assertEqual(uploaded.status_code, 201, uploaded.text)
            self.assertEqual(uploaded.json()["status"], "pending_approval")
            self.assertEqual(uploaded.json()["sha256"], hashlib.sha256(b"setting: approved\n").hexdigest())

            listed = client.get(f"/api/v1/servers/{agent_id}/files", headers=headers)
            self.assertEqual(listed.status_code, 200)
            self.assertTrue(any(item["id"] == uploaded.json()["id"] for item in listed.json()["items"]))
            jobs = client.get("/api/v1/jobs", headers=headers).json()["items"]
            self.assertTrue(any(item["id"] == uploaded.json()["jobId"] and item["action"] == "file.deliver" for item in jobs))


if __name__ == "__main__":
    unittest.main()
