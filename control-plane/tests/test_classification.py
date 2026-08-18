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

from app.main import AUTO_REFRESH_ACTIONS, AuditEvent, FileTransfer, Inventory, Job, RecordingDeletionRequest, RemoteSession, Server, SessionLocal, SystemSetting, User, classify_os, guacamole_launch_url, guacamole_rdp_certificate_fingerprint, guacamole_ssh_host_key, issue_jwt, prune_audit_events, recording_file, recording_probe, retire_legacy_pending_jobs, settings, validate_firewall_job_parameters, validate_job_parameters, validate_log_sources  # noqa: E402
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

    def test_resource_mutations_have_matching_automatic_refreshes(self):
        self.assertEqual(AUTO_REFRESH_ACTIONS["storage.extend"], ("storage.list",))
        self.assertEqual(AUTO_REFRESH_ACTIONS["storage.shrink"], ("storage.list",))
        self.assertEqual(AUTO_REFRESH_ACTIONS["service.restart"], ("service.list",))
        self.assertEqual(AUTO_REFRESH_ACTIONS["user.update"], ("user.list", "group.list"))
        self.assertEqual(AUTO_REFRESH_ACTIONS["process.kill"], ("process.list",))
        self.assertEqual(AUTO_REFRESH_ACTIONS["patch.install"], ("patch.scan",))

    def test_audit_retention_deletes_rows_older_than_thirty_days_and_keeps_anchor(self):
        old_id = str(uuid.uuid4())
        recent_id = str(uuid.uuid4())
        old_hash = hashlib.sha256(old_id.encode()).hexdigest()
        recent_hash = hashlib.sha256(recent_id.encode()).hexdigest()
        with SessionLocal() as db:
            db.add_all([
                AuditEvent(id=old_id, occurred_at=datetime.now(UTC) - timedelta(days=31), actor="old-user", action="test.old", target="expired", detail={"test": True}, previous_hash="0" * 64, event_hash=old_hash),
                AuditEvent(id=recent_id, occurred_at=datetime.now(UTC), actor="recent-user", action="test.recent", target="kept", detail={"operation": "verify"}, previous_hash=old_hash, event_hash=recent_hash),
            ])
            db.flush()
            self.assertGreaterEqual(prune_audit_events(db), 1)
            db.commit()
            self.assertIsNone(db.get(AuditEvent, old_id))
            self.assertIsNotNone(db.get(AuditEvent, recent_id))
            anchor = json.loads(db.get(SystemSetting, "audit_retention_anchor").value)
            self.assertEqual(anchor["lastDeletedHash"], old_hash)
            self.assertEqual(anchor["retentionDays"], 30)

        with TestClient(app) as client:
            token = self.login_admin(client)
            response = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            self.assertEqual(payload["retentionDays"], 30)
            row = next(item for item in payload["items"] if item["id"] == recent_id)
            self.assertEqual(row["detail"], {"operation": "verify"})
            paged = client.get("/api/v1/audit", params={"before": (datetime.now(UTC) + timedelta(days=1)).isoformat()}, headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(paged.status_code, 200, paged.text)

    def test_storage_actions_must_match_the_server_os(self):
        windows = Server(id=str(uuid.uuid4()), name="win", os_family="windows", os_name="Windows Server")
        linux = Server(id=str(uuid.uuid4()), name="linux", os_family="linux", os_name="Ubuntu")
        validate_job_parameters("storage.extend", {"kind": "windows_partition", "disk_number": 0, "partition_number": 2, "add_bytes": 1024**3}, windows)
        validate_job_parameters("storage.shrink", {"kind": "windows_partition", "disk_number": 0, "partition_number": 2, "shrink_bytes": 1024**3}, windows)
        validate_job_parameters("storage.create", {"kind": "linux_lv", "vg_name": "vg0", "name": "data", "size_bytes": 1024**3}, linux)
        with self.assertRaisesRegex(Exception, "operating system"):
            validate_job_parameters("storage.extend", {"kind": "linux_partition", "path": "/dev/sda1", "add_bytes": 1024**3}, windows)
        with self.assertRaisesRegex(Exception, "operating system"):
            validate_job_parameters("storage.shrink", {"kind": "windows_partition", "disk_number": 0, "partition_number": 2, "shrink_bytes": 1024**3}, linux)
        with self.assertRaisesRegex(Exception, "operating system"):
            validate_job_parameters("storage.extend", {"kind": "linux_vg", "name": "vg0", "add_bytes": 1024**3}, linux)
        with self.assertRaisesRegex(Exception, "unsupported"):
            validate_job_parameters("storage.delete", {"kind": "linux_lv", "path": "/dev/vg0/data", "command": "rm -rf /"}, linux)

    def test_resource_job_payloads_reject_nested_or_malformed_values(self):
        linux = Server(id=str(uuid.uuid4()), name="linux", os_family="linux", os_name="Ubuntu")
        with self.assertRaisesRegex(Exception, "group selection"):
            validate_job_parameters("user.create", {"username": "ops", "password": "CorrectHorse123!", "groups": [{"name": "sudo"}], "is_admin": True}, linux)
        with self.assertRaisesRegex(Exception, "processes"):
            validate_job_parameters("process.kill", {"processes": [{"pid": 1, "name": "systemd", "created": 1.0}]}, linux)
        with self.assertRaisesRegex(Exception, "updates"):
            validate_job_parameters("patch.install", {"updates": [{"id": "openssl", "version": "3", "shell": "reboot"}]}, linux)

    def test_log_source_configuration_is_os_scoped(self):
        windows = Server(id=str(uuid.uuid4()), name="win", os_family="windows", os_name="Windows Server")
        linux = Server(id=str(uuid.uuid4()), name="linux", os_family="linux", os_name="Oracle Linux")
        self.assertEqual(validate_log_sources(windows, ["System", "Application"]), ["System", "Application"])
        self.assertEqual(validate_log_sources(linux, ["journal", "/var/log/messages"]), ["journal", "/var/log/messages"])
        with self.assertRaisesRegex(Exception, "below /var/log"):
            validate_log_sources(linux, ["/etc/shadow"])

    def test_firewall_add_requires_backend_specific_server_scope(self):
        common = {"name": "HTTPS", "direction": "in", "action": "allow", "protocol": "tcp", "local_port": 443}
        invalid = [
            {**common, "backend": "firewalld", "family": "ipv4"},
            {**common, "backend": "nftables", "family": "inet", "table": "nat", "chain": "input"},
            {**common, "backend": "iptables", "family": "ipv4", "table": "filter"},
            {**common, "backend": "windows", "profile": "Work"},
        ]
        for parameters in invalid:
            with self.subTest(backend=parameters["backend"]), self.assertRaises(HTTPException) as raised:
                validate_firewall_job_parameters("firewall.rule.add", parameters)
            self.assertEqual(raised.exception.status_code, 422)

    def test_legacy_pending_jobs_are_cancelled_without_execution(self):
        server_id = str(uuid.uuid4())
        with SessionLocal() as db:
            db.add(Server(id=server_id, name="legacy-pending", os_family="linux", os_name="Ubuntu 24.04"))
            job = Job(server_id=server_id, action="file.deliver", parameters={}, reason="Legacy pending file", status="pending_approval", risk="critical", created_by="legacy-admin")
            db.add(job)
            db.flush()
            transfer = FileTransfer(server_id=server_id, job_id=job.id, original_name="legacy.txt", size_bytes=6, sha256=hashlib.sha256(b"legacy").hexdigest(), status="pending_approval", reason="Legacy pending file", created_by="legacy-admin", content_encrypted=b"cipher", nonce="nonce")
            db.add(transfer)
            db.commit()
            job_id, transfer_id = job.id, transfer.id

        with SessionLocal() as db:
            self.assertEqual(retire_legacy_pending_jobs(db), 1)
            db.commit()
            retired_job = db.get(Job, job_id)
            retired_transfer = db.get(FileTransfer, transfer_id)
            self.assertEqual(retired_job.status, "cancelled")
            self.assertIn("hãy tạo lại", retired_job.output)
            self.assertEqual(retired_transfer.status, "cancelled")
            self.assertIsNone(retired_transfer.content_encrypted)
            self.assertEqual(retired_transfer.nonce, "")

    def test_each_firewall_mutation_result_queues_one_automatic_refresh(self):
        with TestClient(app) as client:
            headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            token_response = client.post("/api/v1/enrollment-tokens", headers=headers, json={"label": "firewall-refresh", "expected_os_family": "linux"})
            agent_id = str(uuid.uuid4())
            agent_key = ec.generate_private_key(ec.SECP256R1())
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)])).sign(agent_key, hashes.SHA256())
            enroll = client.post("/api/v1/enroll", json={"token": token_response.json()["token"], "agent_id": agent_id, "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(), "inventory": {"hostname": "firewall-refresh", "os_family": "linux", "os_name": "Ubuntu 24.04", "os_version": "24.04", "distribution_id": "ubuntu", "architecture": "x86_64", "agent_version": "0.6.5", "addresses": ["10.30.1.70"]}})
            self.assertEqual(enroll.status_code, 201, enroll.text)
            certificate = x509.load_pem_x509_certificate(enroll.json()["certificate"].encode())

            with SessionLocal() as db:
                mutation = Job(server_id=agent_id, action="firewall.rule.add", parameters={}, reason="Add test firewall rule", status="dispatched", risk="high", created_by="test-creator")
                db.add(mutation)
                db.commit()
                mutation_id = mutation.id

            path = f"/api/v1/agent/jobs/{mutation_id}/result"
            result_payload = {"status": "succeeded", "exit_code": 0, "output": "inserted"}
            body, signed_headers = signed_agent_request(agent_key, certificate, path, result_payload)
            result = client.post(path, headers=signed_headers, content=body)
            self.assertEqual(result.status_code, 200, result.text)
            self.assertIsNotNone(result.json()["refresh_job_id"])

            body, signed_headers = signed_agent_request(agent_key, certificate, path, result_payload)
            replay = client.post(path, headers=signed_headers, content=body)
            self.assertEqual(replay.status_code, 200, replay.text)
            self.assertIsNone(replay.json()["refresh_job_id"])

            with SessionLocal() as db:
                failed_mutation = Job(server_id=agent_id, action="firewall.rule.remove", parameters={}, reason="Remove test firewall rule", status="dispatched", risk="high", created_by="test-creator")
                db.add(failed_mutation)
                db.commit()
                failed_mutation_id = failed_mutation.id
            failed_path = f"/api/v1/agent/jobs/{failed_mutation_id}/result"
            failed_payload = {"status": "failed", "exit_code": 1, "output": "not removed"}
            body, signed_headers = signed_agent_request(agent_key, certificate, failed_path, failed_payload)
            failed_result = client.post(failed_path, headers=signed_headers, content=body)
            self.assertEqual(failed_result.status_code, 200, failed_result.text)
            self.assertIsNotNone(failed_result.json()["refresh_job_id"])
            global_jobs = client.get("/api/v1/jobs", headers=headers)
            self.assertEqual(global_jobs.status_code, 200, global_jobs.text)
            listed_failure = next(item for item in global_jobs.json()["items"] if item["id"] == failed_mutation_id)
            self.assertEqual(listed_failure["exitCode"], 1)
            self.assertEqual(listed_failure["output"], "not removed")
            with SessionLocal() as db:
                refreshes = db.query(Job).filter(Job.server_id == agent_id, Job.action == "firewall.list").all()
                self.assertEqual(len(refreshes), 2)
                self.assertTrue(all(refresh.status == "queued" for refresh in refreshes))
                self.assertTrue(any(mutation_id[:8] in refresh.reason for refresh in refreshes))
                self.assertTrue(any(failed_mutation_id[:8] in refresh.reason for refresh in refreshes))

    def test_guacamole_host_key_is_a_known_hosts_entry(self):
        encoded_key = base64.b64encode(b"test-ed25519-host-key-material").decode()
        self.assertEqual(
            guacamole_ssh_host_key("10.20.1.11", 22, f"ssh-ed25519 {encoded_key}"),
            f"10.20.1.11 ssh-ed25519 {encoded_key}",
        )
        self.assertEqual(
            guacamole_ssh_host_key("tunnel-relay", 49152, f"old-host ssh-ed25519 {encoded_key} comment"),
            f"[tunnel-relay]:49152 ssh-ed25519 {encoded_key}",
        )

    def test_guacamole_rdp_certificate_pin_uses_freerdp_compatible_separators(self):
        sha1 = "0123456789abcdef0123456789abcdef01234567"
        sha256 = sha1 + "89abcdef0123456789abcdef"
        self.assertEqual(
            guacamole_rdp_certificate_fingerprint(f"sha1:{sha1}"),
            "sha1:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67",
        )
        self.assertEqual(
            guacamole_rdp_certificate_fingerprint(f"sha256:{sha256}"),
            "sha256:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef",
        )
        self.assertIsNone(guacamole_rdp_certificate_fingerprint("sha1:not-a-digest"))

    def test_guacamole_launch_url_opens_the_json_connection_directly(self):
        url = guacamole_launch_url(
            "/guacamole/",
            "dashboard-mgmt",
            "encrypted+/=data",
        )
        encoded_identifier = url.split("/client/", 1)[1].split("?", 1)[0]
        padding = "=" * ((4 - len(encoded_identifier) % 4) % 4)
        self.assertEqual(
            base64.urlsafe_b64decode(encoded_identifier + padding).decode(),
            "dashboard-mgmt\0c\0json",
        )
        self.assertEqual(
            url,
            f"/guacamole/#/client/{encoded_identifier}?data=encrypted%2B%2F%3Ddata",
        )

    def test_guacamole_rejects_invalid_host_key(self):
        with self.assertRaisesRegex(HTTPException, "SSH host key"):
            guacamole_ssh_host_key("10.20.1.11", 22, "ssh-ed25519 not-base64!!!")

    def test_guacamole_rejects_invalid_relay_port(self):
        encoded_key = base64.b64encode(b"test-ed25519-host-key-material").decode()
        with self.assertRaisesRegex(HTTPException, "Cổng SSH relay"):
            guacamole_ssh_host_key("tunnel-relay", 0, f"ssh-ed25519 {encoded_key}")

    def test_agent_package_generation_fails_closed_when_server_ca_is_missing(self):
        assert SessionLocal is not None
        previous_ca_path = settings.caddy_root_ca
        previous_dashboard_url: str | None = None
        had_dashboard_url = False
        settings.caddy_root_ca = str(Path(tmp.name) / "missing-server-ca.crt")
        try:
            with TestClient(app) as client:
                with SessionLocal() as db:
                    existing = db.get(SystemSetting, "dashboard_url")
                    had_dashboard_url = existing is not None
                    previous_dashboard_url = existing.value if existing else None
                    db.merge(SystemSetting(key="dashboard_url", value="https://ops.company.example"))
                    db.commit()
                headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
                status = client.get("/api/v1/agent-packages/status", headers=headers)
                self.assertEqual(status.status_code, 200, status.text)
                self.assertFalse(status.json()["agentTlsCaAvailable"])

                package = client.post(
                    "/api/v1/agent-packages",
                    headers=headers,
                    json={"label": "missing-ca", "os_family": "linux", "expires_minutes": 15},
                )
                self.assertEqual(package.status_code, 503, package.text)
                self.assertIn("caddy-ca-export", package.json()["detail"])

                public_ca = client.get("/api/v1/agent-server-ca")
                self.assertEqual(public_ca.status_code, 503, public_ca.text)
        finally:
            settings.caddy_root_ca = previous_ca_path
            with SessionLocal() as db:
                current = db.get(SystemSetting, "dashboard_url")
                if had_dashboard_url:
                    db.merge(SystemSetting(key="dashboard_url", value=previous_dashboard_url or ""))
                elif current:
                    db.delete(current)
                db.commit()

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

            service_job = client.post(
                "/api/v1/jobs",
                headers=headers,
                json={"server_id": agent_id, "action": "service.list", "parameters": {}, "reason": "Refresh service inventory", "require_approval": False},
            )
            self.assertEqual(service_job.status_code, 201, service_job.text)
            server_jobs = client.get(f"/api/v1/servers/{agent_id}/jobs", headers=headers)
            self.assertEqual(server_jobs.status_code, 200, server_jobs.text)
            listed_job = next(item for item in server_jobs.json()["items"] if item["id"] == service_job.json()["id"])
            self.assertEqual(listed_job["action"], "service.list")
            self.assertIn("output", listed_job)

            direct_job = client.post(
                "/api/v1/jobs",
                headers=headers,
                json={"server_id": agent_id, "action": "system.reboot", "parameters": {}, "reason": "Test direct high-risk execution", "require_approval": True},
            )
            self.assertEqual(direct_job.status_code, 201, direct_job.text)
            self.assertEqual(direct_job.json()["status"], "queued")
            removed_approval_endpoint = client.post(f"/api/v1/jobs/{direct_job.json()['id']}/approve", headers=headers)
            self.assertEqual(removed_approval_endpoint.status_code, 404, removed_approval_endpoint.text)

            invalid_firewall_job = client.post(
                "/api/v1/jobs",
                headers=headers,
                json={"server_id": agent_id, "action": "firewall.rule.add", "parameters": {"backend": "windows", "name": "SSH", "unexpected": "powershell"}, "reason": "Reject unknown firewall parameters"},
            )
            self.assertEqual(invalid_firewall_job.status_code, 422, invalid_firewall_job.text)

            empty_delete = client.post(
                "/api/v1/jobs",
                headers=headers,
                json={"server_id": agent_id, "action": "firewall.rule.remove", "parameters": {"rules": []}, "reason": "Reject empty firewall deletion"},
            )
            self.assertEqual(empty_delete.status_code, 422, empty_delete.text)

            invalid_reorder = client.post(
                "/api/v1/jobs",
                headers=headers,
                json={"server_id": agent_id, "action": "firewall.rule.reorder", "parameters": {"rule": {"backend": "windows", "id": "rule-1", "raw": "block"}, "before": None}, "reason": "Reject unordered firewall backend"},
            )
            self.assertEqual(invalid_reorder.status_code, 422, invalid_reorder.text)

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
            self.assertEqual(status.json()["agentVersion"], (Path(settings.agent_assets_root) / "VERSION").read_text(encoding="ascii").strip())
            self.assertEqual(app.version, status.json()["agentVersion"])
            self.assertTrue(status.json()["windowsMsiAvailable"])
            self.assertTrue(status.json()["agentTlsCaAvailable"])

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
                self.assertEqual(archive.extractfile("VERSION").read().decode().strip(), app.version)
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
                "inventory": {"hostname": "ubuntu-prod-01", "os_family": "linux", "os_name": "Ubuntu 24.04", "os_version": "24.04", "distribution_id": "ubuntu", "architecture": "x86_64", "agent_version": "0.4.2", "addresses": ["10.40.1.10"]},
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
            mismatch = client.post("/api/v1/agent-bootstrap/claim", json={"package_id": package_id, "package_secret": package_secret, "agent_id": mismatch_id, "csr_pem": mismatch_csr.public_bytes(serialization.Encoding.PEM).decode(), "inventory": {"hostname": "wrong-linux", "os_family": "linux", "os_name": "Ubuntu 24.04", "distribution_id": "ubuntu", "agent_version": "0.4.2"}})
            self.assertEqual(mismatch.status_code, 400)

            windows_id = str(uuid.uuid4())
            windows_key = ec.generate_private_key(ec.SECP256R1())
            windows_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, windows_id)])).sign(windows_key, hashes.SHA256())
            windows_claim = client.post("/api/v1/agent-bootstrap/claim", json={"package_id": package_id, "package_secret": package_secret, "agent_id": windows_id, "csr_pem": windows_csr.public_bytes(serialization.Encoding.PEM).decode(), "inventory": {"hostname": "win-prod-01", "os_family": "windows", "os_name": "Microsoft Windows Server 2025", "distribution_id": "windows", "agent_version": "0.4.2"}})
            self.assertEqual(windows_claim.status_code, 201, windows_claim.text)

            settings.web_tls_trust = "system"
            try:
                nginx_status = client.get("/api/v1/agent-packages/status", headers=headers)
                self.assertEqual(nginx_status.status_code, 200, nginx_status.text)
                self.assertEqual(nginx_status.json()["webTlsTrust"], "system")
                nginx_linux = client.post("/api/v1/agent-packages", headers=headers, json={"label": "nginx-linux", "os_family": "linux", "expires_minutes": 15})
                self.assertEqual(nginx_linux.status_code, 200, nginx_linux.text)
                nginx_archive = nginx_linux.content.split(marker, 1)[1]
                with tarfile.open(fileobj=io.BytesIO(nginx_archive), mode="r:gz") as archive:
                    nginx_bootstrap = json.loads(archive.extractfile("bootstrap.json").read())
                    self.assertEqual(nginx_bootstrap["server_ca_sha256"], "system")
                    self.assertEqual(nginx_bootstrap["server_ca_certificate"], "")
                nginx_windows = client.post("/api/v1/agent-packages", headers=headers, json={"label": "nginx-windows", "os_family": "windows", "expires_minutes": 15})
                self.assertEqual(nginx_windows.status_code, 200, nginx_windows.text)
                self.assertIn("--system.msi", nginx_windows.headers["content-disposition"])
            finally:
                settings.web_tls_trust = "internal-ca"

            unsafe_change = client.put("/api/v1/settings/dashboard-url", headers=headers, json={"dashboard_url": "https://ops-new.company.example"})
            self.assertEqual(unsafe_change.status_code, 409)
            confirmed_change = client.put("/api/v1/settings/dashboard-url", headers=headers, json={"dashboard_url": "https://ops-new.company.example", "confirm_existing_agents": True})
            self.assertEqual(confirmed_change.status_code, 200, confirmed_change.text)
            self.assertTrue(confirmed_change.json()["existingAgentsNeedMigration"])

    def test_clean_file_is_encrypted_and_queued_directly(self):
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
            self.assertEqual(uploaded.json()["status"], "queued")
            self.assertEqual(uploaded.json()["note"], "The clean file is queued for the agent")
            self.assertEqual(uploaded.json()["sha256"], hashlib.sha256(b"setting: approved\n").hexdigest())

            listed = client.get(f"/api/v1/servers/{agent_id}/files", headers=headers)
            self.assertEqual(listed.status_code, 200)
            self.assertTrue(any(item["id"] == uploaded.json()["id"] for item in listed.json()["items"]))
            jobs = client.get("/api/v1/jobs", headers=headers).json()["items"]
            self.assertTrue(any(item["id"] == uploaded.json()["jobId"] and item["action"] == "file.deliver" for item in jobs))

    def test_recording_delete_requires_a_distinct_second_admin(self):
        original_root = settings.recording_root
        recording_root = Path(tmp.name) / f"recordings-{uuid.uuid4()}"
        recording_root.mkdir()
        settings.recording_root = str(recording_root)
        server_id = str(uuid.uuid4())
        session_id = str(uuid.uuid4())
        with SessionLocal() as db:
            requester = User(username=f"recording-requester-{uuid.uuid4()}", password_hash="!", display_name="Requester", role="admin")
            approver = User(username=f"recording-approver-{uuid.uuid4()}", password_hash="!", display_name="Approver", role="admin")
            db.add_all([requester, approver, Server(id=server_id, name="recording-test", os_family="linux", os_name="Ubuntu"), RemoteSession(id=session_id, server_id=server_id, protocol="ssh", remote_username="root", created_by=requester.username, status="closed", recording_name=f"{session_id}-${{GUAC_USERNAME}}")])
            db.commit()
            requester_token = issue_jwt(requester)
            approver_token = issue_jwt(approver)
        recording = recording_root / f"{session_id}.guac"
        typescript = recording_root / f"{session_id}.typescript"
        recording.write_bytes(b"guacamole-recording")
        typescript.write_bytes(b"terminal-text")
        try:
            self.assertEqual(recording_file(session_id), recording.resolve())
            with TestClient(app) as client:
                created = client.post("/api/v1/recording-deletion-requests", headers={"Authorization": f"Bearer {requester_token}"}, json={"session_ids": [session_id], "reason": "CHG-4242 retention cleanup"})
                self.assertEqual(created.status_code, 201, created.text)
                deletion_id = created.json()["id"]
                self_approval = client.post(f"/api/v1/recording-deletion-requests/{deletion_id}/approve", headers={"Authorization": f"Bearer {requester_token}"})
                self.assertEqual(self_approval.status_code, 409, self_approval.text)
                self.assertTrue(recording.exists())
                approved = client.post(f"/api/v1/recording-deletion-requests/{deletion_id}/approve", headers={"Authorization": f"Bearer {approver_token}"})
                self.assertEqual(approved.status_code, 200, approved.text)
                self.assertEqual(approved.json()["status"], "deleted")
                self.assertFalse(recording.exists())
                self.assertFalse(typescript.exists())
            with SessionLocal() as db:
                self.assertEqual(db.get(RecordingDeletionRequest, deletion_id).status, "deleted")
        finally:
            settings.recording_root = original_root

    def test_recording_probe_reports_mount_state_instead_of_hiding_it(self):
        original_root = settings.recording_root
        missing_root = Path(tmp.name) / f"missing-recordings-{uuid.uuid4()}"
        session_id = str(uuid.uuid4())
        try:
            settings.recording_root = str(missing_root)
            self.assertEqual(recording_probe(session_id), ([], "root_missing"))
            missing_root.mkdir()
            self.assertEqual(recording_probe(session_id), ([], "not_found"))
            empty = missing_root / f"{session_id}-admin.gly"
            empty.touch()
            self.assertEqual(recording_probe(session_id), ([], "empty"))
            empty.write_bytes(b"guacamole-recording")
            paths, status = recording_probe(session_id)
            self.assertEqual(status, "available")
            self.assertEqual(paths, [empty.resolve()])
        finally:
            settings.recording_root = original_root


if __name__ == "__main__":
    unittest.main()
