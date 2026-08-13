import os
import tempfile
import unittest
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

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

from app.main import Inventory, classify_os  # noqa: E402
from app.main import app, engine  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


class ClassificationTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        engine.dispose()

    def test_windows_is_classified_as_windows(self):
        family, verification = classify_os(Inventory(hostname="win-01", os_family="windows", os_name="Microsoft Windows Server 2025", distribution_id="windows"))
        self.assertEqual((family, verification), ("windows", "verified"))

    def test_ubuntu_is_classified_as_linux(self):
        family, verification = classify_os(Inventory(hostname="ub-01", os_family="linux", os_name="Ubuntu 24.04.3 LTS", distribution_id="ubuntu"))
        self.assertEqual((family, verification), ("linux", "verified"))

    def test_oracle_linux_is_classified_as_linux(self):
        family, verification = classify_os(Inventory(hostname="ol-01", os_family="linux", os_name="Oracle Linux Server 8.10", distribution_id="ol"))
        self.assertEqual((family, verification), ("linux", "verified"))

    def test_login_and_empty_fleet(self):
        with TestClient(app) as client:
            login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "test-only-password-123456"})
            self.assertEqual(login.status_code, 200)
            token = login.json()["access_token"]
            fleet = client.get("/api/v1/servers", headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(fleet.status_code, 200)
            self.assertIsInstance(fleet.json()["items"], list)

    def test_windows_enrollment_is_automatically_categorized(self):
        with TestClient(app) as client:
            login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "test-only-password-123456"})
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            token_response = client.post("/api/v1/enrollment-tokens", headers=headers, json={"label": "windows-test", "expected_os_family": "windows"})
            self.assertEqual(token_response.status_code, 201)

            agent_id = str(uuid.uuid4())
            agent_key = ec.generate_private_key(ec.SECP256R1())
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)])).sign(agent_key, hashes.SHA256())
            enroll = client.post("/api/v1/enroll", json={"token": token_response.json()["token"], "agent_id": agent_id, "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(), "inventory": {"hostname": "win-2025-01", "os_family": "windows", "os_name": "Microsoft Windows Server 2025 Datacenter", "os_version": "26100", "distribution_id": "windows", "architecture": "AMD64", "agent_version": "0.1.0", "addresses": ["10.30.1.50"]}})
            self.assertEqual(enroll.status_code, 201, enroll.text)
            self.assertEqual(enroll.json()["category"], "Windows")

            issued = x509.load_pem_x509_certificate(enroll.json()["certificate"].encode())
            fingerprint = issued.fingerprint(hashes.SHA256()).hex()
            checkin = client.post("/api/v1/agent/checkin", headers={"X-Agent-Cert-Fingerprint": fingerprint, "X-Agent-Cert-Subject": f"CN={agent_id}"}, json={"agent_id": agent_id, "agent_version": "0.1.0", "metrics": {"cpu_percent": 12, "memory_percent": 40, "disk_percent": 30, "uptime_seconds": 3600, "pending_updates": 2, "services_running": 80, "alerts": 0}})
            self.assertEqual(checkin.status_code, 200, checkin.text)

            windows = client.get("/api/v1/servers?os_family=windows", headers=headers)
            self.assertTrue(any(item["id"] == agent_id and item["osFamily"] == "windows" for item in windows.json()["items"]))


if __name__ == "__main__":
    unittest.main()
