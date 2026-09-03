import base64
import hashlib
import io
import json
import os
import shutil
import tempfile
import tarfile
import time
import unittest
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import pyotp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from fastapi.routing import APIRoute
from sqlalchemy import delete, select


def write_artifact_provenance(path: Path, version: str, artifact_kind: str, *, authenticode_signed: bool = False, source_commit: str = "1" * 40) -> Path:
    content = path.read_bytes()
    provenance_path = path.with_name(path.name + ".provenance.json")
    provenance_path.write_text(
        json.dumps(
            {
                "schema": 1,
                "version": version,
                "artifactKind": artifact_kind,
                "sha256": hashlib.sha256(content).hexdigest(),
                "sizeBytes": len(content),
                "sourceCommit": source_commit,
                "authenticodeSigned": authenticode_signed,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return provenance_path


TEST_LINUX_OFFLINE_PROFILES = ("ubuntu-22.04", "ubuntu-24.04", "ol-7", "ol-8", "rhel-7", "rhel-8")


def write_offline_dependency_archive(root: Path, profile: str, version: str, source_commit: str = "1" * 40) -> Path:
    output_dir = root / "linux/offline"
    output_dir.mkdir(parents=True, exist_ok=True)
    package_type = "deb" if profile.startswith("ubuntu-") else "rpm"
    package_name = f"test-storage-tools.{package_type}"
    package_content = f"offline dependency fixture for {profile}".encode()
    manifest = {
        "schema": 1,
        "profile": profile,
        "architecture": "x86_64",
        "packageType": package_type,
        "packages": [{"name": package_name, "sha256": hashlib.sha256(package_content).hexdigest(), "sizeBytes": len(package_content)}],
    }
    archive_path = output_dir / f"{profile}-x86_64.tar.gz"
    with tarfile.open(archive_path, mode="w:gz") as archive:
        package_info = tarfile.TarInfo(f"packages/{package_name}")
        package_info.size = len(package_content)
        archive.addfile(package_info, io.BytesIO(package_content))
        manifest_content = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        manifest_info = tarfile.TarInfo("manifest.json")
        manifest_info.size = len(manifest_content)
        archive.addfile(manifest_info, io.BytesIO(manifest_content))
    content = archive_path.read_bytes()
    provenance = {
        "schema": 1,
        "version": version,
        "artifactKind": "linux_offline_dependencies",
        "profile": profile,
        "architecture": "x86_64",
        "sha256": hashlib.sha256(content).hexdigest(),
        "sizeBytes": len(content),
        "sourceCommit": source_commit,
    }
    archive_path.with_name(archive_path.name + ".provenance.json").write_text(json.dumps(provenance, sort_keys=True), encoding="utf-8")
    return archive_path

tmp = tempfile.TemporaryDirectory()
os.environ["DATABASE_URL"] = f"sqlite:///{Path(tmp.name) / 'test.db'}"
os.environ["JWT_SECRET"] = "test-secret-that-is-not-used-in-production"
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "test-only-password-123456"
os.environ["JOB_SECRET_KEY"] = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
os.environ["FILE_STAGING_ROOT"] = str(Path(tmp.name) / "file-staging")

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
source_agent_assets = Path(__file__).resolve().parents[2] / "agent"
test_agent_assets = Path(tmp.name) / "agent-assets"
(test_agent_assets / "linux/x86_64").mkdir(parents=True)
for asset_name in ("VERSION", "install-linux.sh", "tram-agent.service"):
    shutil.copyfile(source_agent_assets / asset_name, test_agent_assets / asset_name)
fake_linux_agent = bytearray(1024 * 1024)
fake_linux_agent[:6] = b"\x7fELF\x02\x01"
fake_linux_agent[18:20] = b"\x3e\x00"
fake_linux_agent_path = test_agent_assets / "linux/x86_64/tram-agent"
fake_linux_agent_path.write_bytes(fake_linux_agent)
write_artifact_provenance(
    fake_linux_agent_path,
    (test_agent_assets / "VERSION").read_text(encoding="ascii").strip(),
    "linux_elf",
)
for offline_profile in TEST_LINUX_OFFLINE_PROFILES:
    write_offline_dependency_archive(
        test_agent_assets,
        offline_profile,
        (test_agent_assets / "VERSION").read_text(encoding="ascii").strip(),
    )
os.environ["AGENT_ASSETS_ROOT"] = str(test_agent_assets)

from app.main import AUTO_REFRESH_ACTIONS, INITIAL_SERVER_SCAN_ACTIONS, AgentBootstrapPackage, AgentUninstallPolicyState, AuditEvent, AuthThrottle, BulkTask, BulkTaskItem, FileTransfer, FileTransferChunk, Inventory, Job, MFACredential, PlatformRole, RecordingDeletionRequest, RemoteSession, RevokedSessionToken, Server, ServerUserShare, SessionLocal, SystemSetting, User, classify_os, current_user, guacamole_launch_url, guacamole_rdp_certificate_fingerprint, guacamole_ssh_host_key, issue_jwt, password_hasher, prune_audit_events, prune_recording_files, recording_file, recording_probe, retire_legacy_pending_jobs, settings, stream_file_transfer_chunks, synchronize_ldap_users_from_connection, validate_firewall_job_parameters, validate_job_parameters, validate_log_sources  # noqa: E402
from app.main import RemoteCredential, RemoteCredentialUserShare  # noqa: E402
from app.main import app, engine  # noqa: E402
from app.agent_packages import LINUX_AGENT_PATH, linux_run_bundle  # noqa: E402
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


def signed_agent_http_request(private_key: ec.EllipticCurvePrivateKey, certificate: x509.Certificate, method: str, path: str, body: bytes = b"") -> dict[str, str]:
    timestamp = str(int(time.time()))
    message = f"{timestamp}\n{method.upper()}\n{path}\n{hashlib.sha256(body).hexdigest()}".encode()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return {
        "X-Tram-Agent-Certificate": base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode(),
        "X-Tram-Agent-Timestamp": timestamp,
        "X-Tram-Agent-Signature": base64.b64encode(signature).decode(),
    }


def make_agent_identity(agent_id: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .sign(ca_key, hashes.SHA256())
    )
    return private_key, certificate, certificate.fingerprint(hashes.SHA256()).hex()


def agent_checkin_payload(agent_id: str, version: str, *, active_job_ids: list[str] | None = None, uptime_seconds: int = 3600) -> dict:
    active = list(active_job_ids or [])
    return {
        "agent_id": agent_id,
        "agent_version": version,
        "active_job_id": active[0] if active else None,
        "active_job_ids": active,
        "inventory": None,
        "metrics": {
            "cpu_percent": 1,
            "memory_percent": 2,
            "disk_percent": 3,
            "uptime_seconds": uptime_seconds,
            "pending_updates": 0,
            "services_running": 1,
            "alerts": 0,
        },
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

    def test_agent_artifact_provenance_must_match_release_and_bytes(self):
        provenance_path = fake_linux_agent_path.with_name(fake_linux_agent_path.name + ".provenance.json")
        original_provenance = provenance_path.read_text(encoding="utf-8")
        try:
            with TestClient(app) as client:
                headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
                valid = client.get("/api/v1/agent-upgrades/status", headers=headers)
                self.assertEqual(valid.status_code, 200, valid.text)
                linux = valid.json()["artifacts"]["linux"]
                self.assertTrue(linux["ready"])
                self.assertTrue(linux["manifestSigned"])
                self.assertFalse(linux["authenticodeSigned"])
                self.assertEqual(linux["sourceCommit"], "1" * 40)

                mismatched_version = json.loads(original_provenance)
                mismatched_version["version"] = "9.9.9"
                provenance_path.write_text(json.dumps(mismatched_version), encoding="utf-8")
                rejected_version = client.get("/api/v1/agent-upgrades/status", headers=headers)
                self.assertEqual(rejected_version.status_code, 200, rejected_version.text)
                self.assertFalse(rejected_version.json()["artifacts"]["linux"]["ready"])

                mismatched_hash = json.loads(original_provenance)
                mismatched_hash["sha256"] = "0" * 64
                provenance_path.write_text(json.dumps(mismatched_hash), encoding="utf-8")
                rejected_hash = client.get("/api/v1/agent-upgrades/status", headers=headers)
                self.assertEqual(rejected_hash.status_code, 200, rejected_hash.text)
                self.assertFalse(rejected_hash.json()["artifacts"]["linux"]["ready"])

                provenance_path.unlink()
                rejected_missing = client.get("/api/v1/agent-upgrades/status", headers=headers)
                self.assertEqual(rejected_missing.status_code, 200, rejected_missing.text)
                self.assertFalse(rejected_missing.json()["artifacts"]["linux"]["ready"])
        finally:
            provenance_path.write_text(original_provenance, encoding="utf-8")

    def test_linux_manual_package_uses_the_exact_provenance_validated_agent_bytes(self):
        original = fake_linux_agent_path.read_bytes()
        validated = bytearray(original)
        validated[-1] = 0x41
        replaced_on_disk = bytearray(original)
        replaced_on_disk[-1] = 0x42
        try:
            fake_linux_agent_path.write_bytes(replaced_on_disk)
            bundle = linux_run_bundle(
                test_agent_assets,
                agent_content=bytes(validated),
                dashboard_url="https://ops.example.test",
                package_id=str(uuid.uuid4()),
                package_secret="test-only-package-secret",
                ca_certificate="",
                ca_fingerprint="system",
                linux_profile="ubuntu-24.04",
            )
            marker = b"__TRAM_AGENT_ARCHIVE__\n"
            self.assertIn(marker, bundle)
            archive_payload = bundle.split(marker, 1)[1]
            with tarfile.open(fileobj=io.BytesIO(archive_payload), mode="r:gz") as archive:
                member = archive.extractfile(str(LINUX_AGENT_PATH).replace("\\", "/"))
                self.assertIsNotNone(member)
                self.assertEqual(member.read(), bytes(validated))
        finally:
            fake_linux_agent_path.write_bytes(original)

    def test_agent_upgrade_management_uses_signed_artifact_and_two_phase_completion(self):
        agent_id = str(uuid.uuid4())
        legacy_id = str(uuid.uuid4())
        agent_key, agent_certificate, fingerprint = make_agent_identity(agent_id)
        provenance_path = fake_linux_agent_path.with_name(fake_linux_agent_path.name + ".provenance.json")
        original_provenance = provenance_path.read_text(encoding="utf-8")
        # The application lifespan owns schema creation and built-in role seeding.
        with TestClient(app):
            pass
        with SessionLocal() as db:
            db.add_all(
                [Server(
                    id=agent_id,
                    name=f"upgrade-linux-{agent_id[:8]}",
                    address="10.71.1.10",
                    os_family="linux",
                    os_name="Ubuntu 24.04",
                    os_version="24.04",
                    distribution_id="ubuntu",
                    architecture="x86_64",
                    agent_version="0.8.16",
                    cert_fingerprint=fingerprint,
                    last_seen=datetime.now(UTC),
                    status="online",
                ), Server(
                    id=legacy_id,
                    name=f"legacy-upgrade-{legacy_id[:8]}",
                    address="10.71.1.11",
                    os_family="linux",
                    os_name="Ubuntu 22.04",
                    os_version="22.04",
                    distribution_id="ubuntu",
                    architecture="x86_64",
                    agent_version="0.8.15",
                    last_seen=datetime.now(UTC),
                    status="online",
                )]
            )
            db.commit()

        try:
            write_artifact_provenance(fake_linux_agent_path, "0.8.17", "linux_elf")
            with patch("app.main.RELEASE_VERSION", "0.8.17"), TestClient(app) as client:
                admin_headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
                self.assertEqual(client.get("/api/v1/agent-upgrades/status").status_code, 401)

                operator_id = str(uuid.uuid4())
                with SessionLocal() as db:
                    operator = User(id=operator_id, username=f"upgrade-operator-{operator_id[:8]}", password_hash="!test", display_name="Upgrade operator", role="operator", enabled=True)
                    db.add(operator)
                    db.commit()
                    operator_headers = {"Authorization": f"Bearer {issue_jwt(operator)}"}
                self.assertEqual(client.get("/api/v1/agent-upgrades/status", headers=operator_headers).status_code, 403)

                status = client.get("/api/v1/agent-upgrades/status", headers=admin_headers)
                self.assertEqual(status.status_code, 200, status.text)
                self.assertEqual(status.json()["targetVersion"], "0.8.17")
                item = next(entry for entry in status.json()["items"] if entry["serverId"] == agent_id)
                self.assertEqual(item["eligibility"], "eligible")
                self.assertTrue(item["online"])
                legacy_item = next(entry for entry in status.json()["items"] if entry["serverId"] == legacy_id)
                self.assertEqual(legacy_item["eligibility"], "manual_required")
                self.assertIn("0.8.16", legacy_item["reason"])
                self.assertTrue(status.json()["artifacts"]["linux"]["ready"])

                generic = client.post(
                    "/api/v1/jobs",
                    headers=admin_headers,
                    json={"server_id": agent_id, "action": "agent.upgrade", "parameters": {}, "reason": "Must use dedicated lifecycle route"},
                )
                self.assertEqual(generic.status_code, 400, generic.text)

                queued = client.post(
                    "/api/v1/agent-upgrades",
                    headers=admin_headers,
                    json={"server_ids": [agent_id, legacy_id], "reason": "Upgrade the staging Agent from the website"},
                )
                self.assertEqual(queued.status_code, 201, queued.text)
                self.assertEqual(queued.json()["targetVersion"], "0.8.17")
                self.assertEqual(len(queued.json()["queued"]), 1)
                self.assertEqual(queued.json()["skipped"][0]["serverId"], legacy_id)
                job_id = queued.json()["queued"][0]["jobId"]

                with SessionLocal() as db:
                    job = db.get(Job, job_id)
                    self.assertIsNotNone(job)
                    self.assertEqual(job.status, "queued")
                    self.assertEqual(job.risk, "critical")
                    manifest = job.parameters["manifest"]
                    self.assertEqual(manifest["jobId"], job_id)
                    self.assertEqual(manifest["agentId"], agent_id)
                    self.assertEqual(manifest["version"], "0.8.17")
                    artifact = manifest["artifacts"]["linux-x86_64"]
                    self.assertEqual(artifact["osFamily"], "linux")
                    self.assertEqual(artifact["architecture"], "x86_64")
                    self.assertRegex(artifact["sha256"], r"^[0-9a-f]{64}$")
                    self.assertGreater(artifact["size"], 0)
                    self.assertNotIn("private", json.dumps(job.parameters).lower())
                    job.status = "dispatched"
                    db.commit()

                artifact_path = f"/api/v1/agent/upgrades/{job_id}/artifact"
                download_headers = signed_agent_http_request(agent_key, agent_certificate, "GET", artifact_path)
                download = client.get(f"{artifact_path}?agent_id={agent_id}", headers=download_headers)
                self.assertEqual(download.status_code, 200, download.text)
                self.assertEqual(download.headers["x-tram-agent-version"], "0.8.17")
                self.assertEqual(hashlib.sha256(download.content).hexdigest(), download.headers["x-tram-sha256"])

                result_path = f"/api/v1/agent/jobs/{job_id}/result"
                prepared_payload = {"status": "succeeded", "exit_code": 0, "output": "Artifact verified and updater scheduled"}
                prepared_body, prepared_headers = signed_agent_request(agent_key, agent_certificate, result_path, prepared_payload)
                prepared = client.post(result_path, headers=prepared_headers, content=prepared_body)
                self.assertEqual(prepared.status_code, 200, prepared.text)
                self.assertEqual(prepared.json()["status"], "installing")
                with SessionLocal() as db:
                    self.assertEqual(db.get(Job, job_id).status, "installing")

                wrong_payload = {"status": "succeeded", "exit_code": 0, "output": "Wrong binary", "agent_version": "0.8.18"}
                wrong_body, wrong_headers = signed_agent_request(agent_key, agent_certificate, result_path, wrong_payload)
                wrong = client.post(result_path, headers=wrong_headers, content=wrong_body)
                self.assertEqual(wrong.status_code, 409, wrong.text)
                with SessionLocal() as db:
                    self.assertEqual(db.get(Job, job_id).status, "installing")
                    self.assertEqual(db.get(Server, agent_id).agent_version, "0.8.16")

                complete_payload = {"status": "succeeded", "exit_code": 0, "output": "Agent 0.8.17 is running", "agent_version": "0.8.17"}
                complete_body, complete_headers = signed_agent_request(agent_key, agent_certificate, result_path, complete_payload)
                complete = client.post(result_path, headers=complete_headers, content=complete_body)
                self.assertEqual(complete.status_code, 200, complete.text)
                self.assertEqual(complete.json()["status"], "succeeded")
                with SessionLocal() as db:
                    self.assertEqual(db.get(Job, job_id).status, "succeeded")
                    self.assertEqual(db.get(Server, agent_id).agent_version, "0.8.17")

                refreshed = client.get("/api/v1/agent-upgrades/status", headers=admin_headers)
                refreshed_item = next(entry for entry in refreshed.json()["items"] if entry["serverId"] == agent_id)
                self.assertEqual(refreshed_item["eligibility"], "current")
                self.assertIsNone(refreshed_item["activeJobId"])
        finally:
            provenance_path.write_text(original_provenance, encoding="utf-8")
            with SessionLocal() as db:
                task_ids = db.execute(select(BulkTaskItem.bulk_task_id).where(BulkTaskItem.server_id == agent_id)).scalars().all()
                db.execute(delete(BulkTaskItem).where(BulkTaskItem.server_id == agent_id))
                if task_ids:
                    db.execute(delete(BulkTask).where(BulkTask.id.in_(task_ids)))
                db.execute(delete(AgentUninstallPolicyState).where(AgentUninstallPolicyState.server_id.in_([agent_id, legacy_id])))
                db.execute(delete(Job).where(Job.server_id.in_([agent_id, legacy_id])))
                db.execute(delete(Server).where(Server.id.in_([agent_id, legacy_id])))
                db.execute(delete(User).where(User.username.like("upgrade-operator-%")))
                db.commit()

    def test_agent_uninstall_password_is_hashed_rotated_and_applied_only_to_compatible_agents(self):
        compatible_id = str(uuid.uuid4())
        legacy_id = str(uuid.uuid4())
        agent_key, agent_certificate, fingerprint = make_agent_identity(compatible_id)
        password_v1 = "Uninstall-stage-secret-v1!"
        password_v2 = "Uninstall-stage-secret-v2!"
        setting_key = "agent_uninstall_password_v1"
        with TestClient(app):
            pass
        with SessionLocal() as db:
            previous = db.get(SystemSetting, setting_key)
            previous_value = previous.value if previous else None
            if previous:
                db.delete(previous)
            db.add_all(
                [
                    Server(id=compatible_id, name=f"protected-{compatible_id[:8]}", os_family="windows", os_name="Windows Server 2022", architecture="AMD64", agent_version="0.8.16", cert_fingerprint=fingerprint, status="online", last_seen=datetime.now(UTC)),
                    Server(id=legacy_id, name=f"legacy-{legacy_id[:8]}", os_family="linux", os_name="Ubuntu 24.04", architecture="x86_64", agent_version="0.8.15", status="online", last_seen=datetime.now(UTC)),
                ]
            )
            db.commit()

        try:
            with TestClient(app) as client:
                admin_headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
                self.assertEqual(client.get("/api/v1/settings/agent-uninstall-protection").status_code, 401)

                leaked_candidates = ["new-leak", "confirm-leak", "current-leak-" + ("x" * 1100)]
                invalid_secret = client.put(
                    "/api/v1/settings/agent-uninstall-protection",
                    headers=admin_headers,
                    json={
                        "new_password": leaked_candidates[0],
                        "confirm_password": leaked_candidates[1],
                        "current_password": leaked_candidates[2],
                        "reason": "Validate that rejected secrets are always redacted",
                    },
                )
                self.assertEqual(invalid_secret.status_code, 422, invalid_secret.text)
                for candidate in leaked_candidates:
                    self.assertNotIn(candidate, invalid_secret.text)
                self.assertNotIn('"input"', invalid_secret.text)

                mismatch = client.put(
                    "/api/v1/settings/agent-uninstall-protection",
                    headers=admin_headers,
                    json={"new_password": password_v1, "confirm_password": password_v2, "reason": "Configure protected uninstall on managed endpoints"},
                )
                self.assertEqual(mismatch.status_code, 422, mismatch.text)

                configured = client.put(
                    "/api/v1/settings/agent-uninstall-protection",
                    headers=admin_headers,
                    json={"new_password": password_v1, "confirm_password": password_v1, "reason": "Configure protected uninstall on managed endpoints"},
                )
                self.assertEqual(configured.status_code, 200, configured.text)
                self.assertTrue(configured.json()["configured"])
                self.assertEqual(configured.json()["revision"], 1)
                compatible_item = next(entry for entry in configured.json()["items"] if entry["serverId"] == compatible_id)
                legacy_item = next(entry for entry in configured.json()["items"] if entry["serverId"] == legacy_id)
                self.assertEqual(compatible_item["status"], "queued")
                self.assertEqual(legacy_item["status"], "manual_required")

                with SessionLocal() as db:
                    stored = db.get(SystemSetting, setting_key)
                    self.assertIsNotNone(stored)
                    self.assertNotIn(password_v1, stored.value)
                    policy = json.loads(stored.value)
                    self.assertEqual(set(policy), {"version", "revision", "algorithm", "iterations", "salt", "verifier", "updated_at", "updated_by"})
                    self.assertEqual(policy["algorithm"], "pbkdf2-sha256")
                    self.assertEqual(policy["iterations"], 600_000)
                    first_job = db.execute(select(Job).where(Job.server_id == compatible_id, Job.action == "agent.uninstall.policy").order_by(Job.created_at.desc())).scalars().first()
                    self.assertIsNotNone(first_job)
                    first_job_id = first_job.id
                    raw_parameters = json.dumps(first_job.parameters)
                    self.assertNotIn(password_v1, raw_parameters)
                    self.assertIn("__tram_encrypted__", raw_parameters)
                    self.assertIsNone(db.execute(select(Job).where(Job.server_id == legacy_id, Job.action == "agent.uninstall.policy")).scalar_one_or_none())
                    # Simulate the real race: revision 1 has already left the
                    # queue when an administrator rotates to revision 2.
                    first_job.status = "dispatched"
                    first_job.started_at = datetime.now(UTC)
                    db.commit()

                denied = client.put(
                    "/api/v1/settings/agent-uninstall-protection",
                    headers=admin_headers,
                    json={"current_password": "not-the-current-password", "new_password": password_v2, "confirm_password": password_v2, "reason": "Rotate protected uninstall credential"},
                )
                self.assertEqual(denied.status_code, 401, denied.text)

                rotated = client.put(
                    "/api/v1/settings/agent-uninstall-protection",
                    headers=admin_headers,
                    json={"current_password": password_v1, "new_password": password_v2, "confirm_password": password_v2, "reason": "Rotate protected uninstall credential"},
                )
                self.assertEqual(rotated.status_code, 200, rotated.text)
                self.assertEqual(rotated.json()["revision"], 2)

                with SessionLocal() as db:
                    first_job = db.get(Job, first_job_id)
                    self.assertEqual(first_job.status, "dispatched")
                    self.assertEqual(
                        db.execute(select(Job).where(Job.server_id == compatible_id, Job.action == "agent.uninstall.policy", Job.id != first_job_id)).scalars().all(),
                        [],
                    )
                    state = db.get(AgentUninstallPolicyState, compatible_id)
                    self.assertEqual(state.desired_revision, 2)
                    self.assertEqual(state.job_id, first_job_id)
                    self.assertEqual(state.status, "dispatched")
                    stored_text = db.get(SystemSetting, setting_key).value
                    audit_text = json.dumps(
                        [
                            {"action": event.action, "result": event.result, "detail": event.detail}
                            for event in db.execute(select(AuditEvent).where(AuditEvent.action.in_(["agent.uninstall.protection.update", "agent.uninstall.policy.queued"]))).scalars().all()
                        ],
                        ensure_ascii=False,
                    )
                    self.assertNotIn(password_v1, stored_text + audit_text + json.dumps(first_job.parameters))
                    self.assertNotIn(password_v2, stored_text + audit_text + json.dumps(first_job.parameters))

                first_result_path = f"/api/v1/agent/jobs/{first_job_id}/result"
                first_result_payload = {"status": "succeeded", "exit_code": 0, "output": "Uninstall protection revision 1 installed"}
                first_result_body, first_result_headers = signed_agent_request(agent_key, agent_certificate, first_result_path, first_result_payload)
                first_result = client.post(first_result_path, headers=first_result_headers, content=first_result_body)
                self.assertEqual(first_result.status_code, 200, first_result.text)
                with SessionLocal() as db:
                    state = db.get(AgentUninstallPolicyState, compatible_id)
                    self.assertEqual(state.desired_revision, 2)
                    self.assertEqual(state.applied_revision, 1)
                    self.assertEqual(state.status, "pending")
                    self.assertIsNone(state.job_id)

                checkin_payload = agent_checkin_payload(compatible_id, "0.8.16", uptime_seconds=3601)
                checkin_body, checkin_headers = signed_agent_request(agent_key, agent_certificate, "/api/v1/agent/checkin", checkin_payload)
                checkin = client.post("/api/v1/agent/checkin", headers=checkin_headers, content=checkin_body)
                self.assertEqual(checkin.status_code, 200, checkin.text)
                policy_jobs = [job for job in checkin.json()["jobs"] if job["action"] == "agent.uninstall.policy"]
                self.assertEqual(len(policy_jobs), 1)
                second_job_id = policy_jobs[0]["id"]
                self.assertEqual(policy_jobs[0]["parameters"]["revision"], 2)

                second_result_path = f"/api/v1/agent/jobs/{second_job_id}/result"
                second_result_payload = {"status": "succeeded", "exit_code": 0, "output": "Uninstall protection revision 2 installed"}
                second_result_body, second_result_headers = signed_agent_request(agent_key, agent_certificate, second_result_path, second_result_payload)
                second_result = client.post(second_result_path, headers=second_result_headers, content=second_result_body)
                self.assertEqual(second_result.status_code, 200, second_result.text)

                applied = client.get("/api/v1/settings/agent-uninstall-protection", headers=admin_headers)
                self.assertEqual(applied.status_code, 200, applied.text)
                applied_item = next(entry for entry in applied.json()["items"] if entry["serverId"] == compatible_id)
                self.assertEqual(applied_item["status"], "applied")
                self.assertEqual(applied_item["appliedRevision"], 2)

                generic = client.post(
                    "/api/v1/jobs",
                    headers=admin_headers,
                    json={"server_id": compatible_id, "action": "agent.uninstall.policy", "parameters": {"revision": 99, "secret": "not-allowed"}, "reason": "Must use dedicated lifecycle route"},
                )
                self.assertEqual(generic.status_code, 400, generic.text)
        finally:
            with SessionLocal() as db:
                db.execute(delete(AgentUninstallPolicyState).where(AgentUninstallPolicyState.server_id.in_([compatible_id, legacy_id])))
                db.execute(delete(Job).where(Job.server_id.in_([compatible_id, legacy_id])))
                db.execute(delete(Server).where(Server.id.in_([compatible_id, legacy_id])))
                current = db.get(SystemSetting, setting_key)
                if previous_value is None:
                    if current:
                        db.delete(current)
                else:
                    db.merge(SystemSetting(key=setting_key, value=previous_value))
                db.commit()

    def test_agent_uninstall_policy_retries_with_backoff_and_stops_after_three_failures(self):
        agent_id = str(uuid.uuid4())
        agent_key, agent_certificate, fingerprint = make_agent_identity(agent_id)
        setting_key = "agent_uninstall_password_v1"
        password = "Retry-policy-secret-123!"
        with TestClient(app):
            pass
        with SessionLocal() as db:
            previous = db.get(SystemSetting, setting_key)
            previous_value = previous.value if previous else None
            if previous:
                db.delete(previous)
            db.add(
                Server(
                    id=agent_id,
                    name=f"retry-policy-{agent_id[:8]}",
                    os_family="linux",
                    os_name="Ubuntu 24.04",
                    architecture="x86_64",
                    agent_version="0.8.16",
                    cert_fingerprint=fingerprint,
                    status="online",
                    last_seen=datetime.now(UTC),
                )
            )
            db.commit()

        uptime = 4100

        def checkin(client: TestClient) -> dict:
            nonlocal uptime
            uptime += 1
            payload = agent_checkin_payload(agent_id, "0.8.16", uptime_seconds=uptime)
            body, headers = signed_agent_request(agent_key, agent_certificate, "/api/v1/agent/checkin", payload)
            response = client.post("/api/v1/agent/checkin", headers=headers, content=body)
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        try:
            with TestClient(app) as client:
                admin_headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
                configured = client.put(
                    "/api/v1/settings/agent-uninstall-protection",
                    headers=admin_headers,
                    json={"new_password": password, "confirm_password": password, "reason": "Test bounded policy delivery retries"},
                )
                self.assertEqual(configured.status_code, 200, configured.text)
                with SessionLocal() as db:
                    state = db.get(AgentUninstallPolicyState, agent_id)
                    self.assertIsNotNone(state)
                    current_job_id = state.job_id

                dispatched = checkin(client)
                policy_jobs = [job for job in dispatched["jobs"] if job["action"] == "agent.uninstall.policy"]
                self.assertEqual([job["id"] for job in policy_jobs], [current_job_id])

                for attempt in range(1, 4):
                    result_path = f"/api/v1/agent/jobs/{current_job_id}/result"
                    result_payload = {"status": "failed", "exit_code": 1, "output": f"policy sync failure {attempt}"}
                    result_body, result_headers = signed_agent_request(agent_key, agent_certificate, result_path, result_payload)
                    result = client.post(result_path, headers=result_headers, content=result_body)
                    self.assertEqual(result.status_code, 200, result.text)
                    with SessionLocal() as db:
                        state = db.get(AgentUninstallPolicyState, agent_id)
                        self.assertEqual(state.status, "failed")
                        failure = json.loads(state.error)
                        self.assertEqual(failure["attempts"], attempt)
                        self.assertEqual(failure["message"], f"policy sync failure {attempt}")

                    immediate = checkin(client)
                    self.assertFalse(any(job["action"] == "agent.uninstall.policy" for job in immediate["jobs"]))

                    with SessionLocal() as db:
                        state = db.get(AgentUninstallPolicyState, agent_id)
                        # Move beyond even the third exponential backoff. The
                        # first two attempts may retry; the third must remain
                        # terminal until an administrator creates a new policy revision.
                        state.updated_at = datetime.now(UTC) - timedelta(hours=2)
                        db.commit()
                    retry = checkin(client)
                    retry_jobs = [job for job in retry["jobs"] if job["action"] == "agent.uninstall.policy"]
                    if attempt < 3:
                        self.assertEqual(len(retry_jobs), 1)
                        current_job_id = retry_jobs[0]["id"]
                    else:
                        self.assertEqual(retry_jobs, [])

                summary = client.get("/api/v1/settings/agent-uninstall-protection", headers=admin_headers)
                self.assertEqual(summary.status_code, 200, summary.text)
                self.assertEqual(summary.json()["failedAgents"], 1)
                item = next(entry for entry in summary.json()["items"] if entry["serverId"] == agent_id)
                self.assertEqual(item["status"], "failed")
        finally:
            with SessionLocal() as db:
                db.execute(delete(AgentUninstallPolicyState).where(AgentUninstallPolicyState.server_id == agent_id))
                db.execute(delete(Job).where(Job.server_id == agent_id))
                db.execute(delete(Server).where(Server.id == agent_id))
                current = db.get(SystemSetting, setting_key)
                if previous_value is None:
                    if current:
                        db.delete(current)
                else:
                    db.merge(SystemSetting(key=setting_key, value=previous_value))
                db.commit()

    def test_agent_upgrade_timeout_accepts_late_result_and_target_version_checkin(self):
        agent_id = str(uuid.uuid4())
        agent_key, agent_certificate, fingerprint = make_agent_identity(agent_id)
        late_job_id = str(uuid.uuid4())
        checkin_job_id = str(uuid.uuid4())
        with TestClient(app):
            pass
        with SessionLocal() as db:
            db.add(
                Server(
                    id=agent_id,
                    name=f"timeout-upgrade-{agent_id[:8]}",
                    os_family="linux",
                    os_name="Ubuntu 24.04",
                    architecture="x86_64",
                    agent_version="0.8.16",
                    cert_fingerprint=fingerprint,
                    status="online",
                    last_seen=datetime.now(UTC),
                )
            )
            db.add(
                Job(
                    id=late_job_id,
                    server_id=agent_id,
                    action="agent.upgrade",
                    parameters={"manifest": {"version": "0.8.17"}},
                    reason="Exercise timeout reconciliation by late result",
                    status="installing",
                    risk="critical",
                    created_by="system-test",
                    started_at=datetime.now(UTC) - timedelta(minutes=46),
                )
            )
            db.commit()

        try:
            with TestClient(app) as client:
                admin_headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
                status = client.get("/api/v1/agent-upgrades/status", headers=admin_headers)
                self.assertEqual(status.status_code, 200, status.text)
                with SessionLocal() as db:
                    timed_out = db.get(Job, late_job_id)
                    self.assertEqual(timed_out.status, "failed")
                    self.assertEqual(timed_out.exit_code, 124)
                    self.assertEqual(json.loads(timed_out.output)["timeout"], "agent-upgrade-install-timeout-v1")

                late_path = f"/api/v1/agent/jobs/{late_job_id}/result"
                late_payload = {"status": "succeeded", "exit_code": 0, "output": "Agent restarted after a delayed report", "agent_version": "0.8.17"}
                late_body, late_headers = signed_agent_request(agent_key, agent_certificate, late_path, late_payload)
                late = client.post(late_path, headers=late_headers, content=late_body)
                self.assertEqual(late.status_code, 200, late.text)
                self.assertEqual(late.json()["status"], "succeeded")
                with SessionLocal() as db:
                    self.assertEqual(db.get(Job, late_job_id).status, "succeeded")
                    self.assertEqual(db.get(Server, agent_id).agent_version, "0.8.17")
                    db.add(
                        Job(
                            id=checkin_job_id,
                            server_id=agent_id,
                            action="agent.upgrade",
                            parameters={"manifest": {"version": "0.8.18"}},
                            reason="Exercise timeout reconciliation by check-in",
                            status="installing",
                            risk="critical",
                            created_by="system-test",
                            started_at=datetime.now(UTC) - timedelta(minutes=46),
                        )
                    )
                    db.commit()

                checkin_payload = agent_checkin_payload(agent_id, "0.8.18", uptime_seconds=5100)
                checkin_body, checkin_headers = signed_agent_request(agent_key, agent_certificate, "/api/v1/agent/checkin", checkin_payload)
                checkin = client.post("/api/v1/agent/checkin", headers=checkin_headers, content=checkin_body)
                self.assertEqual(checkin.status_code, 200, checkin.text)
                self.assertFalse(any(job["action"] == "agent.upgrade" for job in checkin.json()["jobs"]))
                with SessionLocal() as db:
                    reconciled = db.get(Job, checkin_job_id)
                    self.assertEqual(reconciled.status, "succeeded")
                    self.assertEqual(reconciled.exit_code, 0)
                    self.assertTrue(json.loads(reconciled.output)["confirmedAfterTimeout"])
                    timeout_audits = db.execute(
                        select(AuditEvent).where(
                            AuditEvent.action == "agent.upgrade.timeout.failed",
                            AuditEvent.target.in_([late_job_id, checkin_job_id]),
                        )
                    ).scalars().all()
                    self.assertEqual({event.target for event in timeout_audits}, {late_job_id, checkin_job_id})
        finally:
            with SessionLocal() as db:
                db.execute(delete(AgentUninstallPolicyState).where(AgentUninstallPolicyState.server_id == agent_id))
                db.execute(delete(Job).where(Job.server_id == agent_id))
                db.execute(delete(Server).where(Server.id == agent_id))
                db.commit()

    def test_agent_upgrade_waits_for_active_work_and_blocks_later_dispatch(self):
        agent_id = str(uuid.uuid4())
        agent_key, agent_certificate, fingerprint = make_agent_identity(agent_id)
        active_read_id = str(uuid.uuid4())
        upgrade_id = str(uuid.uuid4())
        later_read_id = str(uuid.uuid4())
        with TestClient(app):
            pass
        created = datetime.now(UTC)
        with SessionLocal() as db:
            db.add(
                Server(
                    id=agent_id,
                    name=f"upgrade-drain-{agent_id[:8]}",
                    os_family="linux",
                    os_name="Ubuntu 24.04",
                    architecture="x86_64",
                    agent_version="0.8.16",
                    cert_fingerprint=fingerprint,
                    status="online",
                    last_seen=created,
                )
            )
            db.add_all(
                [
                    Job(
                        id=active_read_id,
                        server_id=agent_id,
                        action="service.list",
                        parameters={},
                        reason="Read already active before the upgrade",
                        status="dispatched",
                        risk="low",
                        created_by="system-test",
                        created_at=created,
                        started_at=created,
                    ),
                    Job(
                        id=upgrade_id,
                        server_id=agent_id,
                        action="agent.upgrade",
                        parameters={"manifest": {"version": "0.8.17"}},
                        reason="Upgrade must drain all existing work",
                        status="queued",
                        risk="critical",
                        created_by="system-test",
                        created_at=created + timedelta(seconds=1),
                    ),
                    Job(
                        id=later_read_id,
                        server_id=agent_id,
                        action="process.list",
                        parameters={},
                        reason="Read queued after the upgrade barrier",
                        status="queued",
                        risk="low",
                        created_by="system-test",
                        created_at=created + timedelta(seconds=2),
                    ),
                ]
            )
            db.commit()

        def checkin(client: TestClient, active: list[str]) -> dict:
            body, headers = signed_agent_request(
                agent_key,
                agent_certificate,
                "/api/v1/agent/checkin",
                agent_checkin_payload(agent_id, "0.8.16", active_job_ids=active, uptime_seconds=6200),
            )
            response = client.post("/api/v1/agent/checkin", headers=headers, content=body)
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        try:
            with TestClient(app) as client:
                draining = checkin(client, [active_read_id])
                self.assertEqual(draining["jobs"], [])
                with SessionLocal() as db:
                    self.assertEqual(db.get(Job, later_read_id).status, "queued")

                result_path = f"/api/v1/agent/jobs/{active_read_id}/result"
                result_body, result_headers = signed_agent_request(
                    agent_key,
                    agent_certificate,
                    result_path,
                    {"status": "succeeded", "exit_code": 0, "output": "[]"},
                )
                result = client.post(result_path, headers=result_headers, content=result_body)
                self.assertEqual(result.status_code, 200, result.text)

                dispatched = checkin(client, [])
                self.assertEqual([job["id"] for job in dispatched["jobs"]], [upgrade_id])
                with SessionLocal() as db:
                    upgrade = db.get(Job, upgrade_id)
                    upgrade.status = "installing"
                    upgrade.started_at = datetime.now(UTC)
                    db.commit()

                blocked = checkin(client, [])
                self.assertEqual(blocked["jobs"], [])
                with SessionLocal() as db:
                    self.assertEqual(db.get(Job, later_read_id).status, "queued")
        finally:
            with SessionLocal() as db:
                db.execute(delete(Job).where(Job.server_id == agent_id))
                db.execute(delete(Server).where(Server.id == agent_id))
                db.commit()

    def test_agent_uninstall_event_requires_signed_identity_and_is_audited(self):
        agent_id = str(uuid.uuid4())
        agent_key, agent_certificate, fingerprint = make_agent_identity(agent_id)
        with TestClient(app):
            pass
        with SessionLocal() as db:
            db.add(
                Server(
                    id=agent_id,
                    name=f"uninstall-audit-{agent_id[:8]}",
                    os_family="windows",
                    os_name="Windows Server 2022",
                    architecture="AMD64",
                    agent_version="0.8.16",
                    cert_fingerprint=fingerprint,
                    status="online",
                    last_seen=datetime.now(UTC),
                )
            )
            db.commit()
        payload = {"agent_id": agent_id, "event": "denied", "os_user": "LAB\\operator", "detail": "invalid uninstall password"}
        try:
            with TestClient(app) as client:
                self.assertEqual(client.post("/api/v1/agent/uninstall-event", json=payload).status_code, 401)
                body, headers = signed_agent_request(agent_key, agent_certificate, "/api/v1/agent/uninstall-event", payload)
                accepted = client.post("/api/v1/agent/uninstall-event", headers=headers, content=body)
                self.assertEqual(accepted.status_code, 202, accepted.text)
                with SessionLocal() as db:
                    event = db.execute(
                        select(AuditEvent)
                        .where(AuditEvent.action == "agent.uninstall.denied", AuditEvent.target == agent_id)
                        .order_by(AuditEvent.occurred_at.desc())
                    ).scalars().first()
                    self.assertIsNotNone(event)
                    self.assertEqual(event.actor, f"agent:{agent_id}")
                    self.assertEqual(event.result, "denied")
                    self.assertEqual(event.detail["os_user"], "LAB\\operator")

                completed_payload = {"agent_id": agent_id, "event": "completed", "os_user": "LAB\\operator", "detail": "supported uninstaller finished"}
                completed_body, completed_headers = signed_agent_request(agent_key, agent_certificate, "/api/v1/agent/uninstall-event", completed_payload)
                completed = client.post("/api/v1/agent/uninstall-event", headers=completed_headers, content=completed_body)
                self.assertEqual(completed.status_code, 202, completed.text)
                with SessionLocal() as db:
                    server = db.get(Server, agent_id)
                    self.assertEqual(server.cert_fingerprint, "")
                    self.assertEqual(server.status, "uninstalled")
                    completed_event = db.execute(
                        select(AuditEvent)
                        .where(AuditEvent.action == "agent.uninstall.completed", AuditEvent.target == agent_id)
                        .order_by(AuditEvent.occurred_at.desc())
                    ).scalars().first()
                    self.assertIsNotNone(completed_event)
                    self.assertEqual(completed_event.result, "success")

                admin_headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
                upgrade_status = client.get("/api/v1/agent-upgrades/status", headers=admin_headers)
                self.assertEqual(upgrade_status.status_code, 200, upgrade_status.text)
                self.assertNotIn(agent_id, {item["serverId"] for item in upgrade_status.json()["items"]})
                uninstall_status = client.get("/api/v1/settings/agent-uninstall-protection", headers=admin_headers)
                self.assertEqual(uninstall_status.status_code, 200, uninstall_status.text)
                self.assertNotIn(agent_id, {item["serverId"] for item in uninstall_status.json()["items"]})

                replay_body, replay_headers = signed_agent_request(agent_key, agent_certificate, "/api/v1/agent/uninstall-event", {**completed_payload, "event": "authorized"})
                replay = client.post("/api/v1/agent/uninstall-event", headers=replay_headers, content=replay_body)
                self.assertEqual(replay.status_code, 401, replay.text)
        finally:
            with SessionLocal() as db:
                db.execute(delete(AuditEvent).where(AuditEvent.target == agent_id))
                db.execute(delete(Server).where(Server.id == agent_id))
                db.commit()

    def test_custom_agent_manager_is_share_scoped_and_cannot_manage_uninstall_password(self):
        role_name = f"agentmgr-{uuid.uuid4().hex[:8]}"
        user_id = str(uuid.uuid4())
        visible_id = str(uuid.uuid4())
        hidden_id = str(uuid.uuid4())
        provenance_path = fake_linux_agent_path.with_name(fake_linux_agent_path.name + ".provenance.json")
        original_provenance = provenance_path.read_text(encoding="utf-8")
        with TestClient(app):
            pass
        with SessionLocal() as db:
            role = PlatformRole(
                name=role_name,
                display_name="Scoped Agent manager",
                description="Test role with Agent lifecycle permission",
                permissions=["agents.manage"],
                system=False,
            )
            user = User(
                id=user_id,
                username=f"agentmgr-{user_id[:8]}",
                password_hash="!test",
                display_name="Scoped Agent manager",
                role=role_name,
                enabled=True,
            )
            db.add_all(
                [
                    role,
                    user,
                    Server(id=visible_id, name=f"visible-{visible_id[:8]}", os_family="linux", os_name="Ubuntu 24.04", architecture="x86_64", agent_version="0.8.16", status="online", last_seen=datetime.now(UTC)),
                    Server(id=hidden_id, name=f"hidden-{hidden_id[:8]}", os_family="linux", os_name="Ubuntu 24.04", architecture="x86_64", agent_version="0.8.16", status="online", last_seen=datetime.now(UTC)),
                ]
            )
            db.flush()
            db.add(ServerUserShare(server_id=visible_id, user_id=user_id, granted_by="system-test"))
            db.commit()
            headers = {"Authorization": f"Bearer {issue_jwt(user)}"}
        try:
            with TestClient(app) as client:
                status = client.get("/api/v1/agent-upgrades/status", headers=headers)
                self.assertEqual(status.status_code, 200, status.text)
                self.assertEqual({item["serverId"] for item in status.json()["items"]}, {visible_id})
                write_artifact_provenance(fake_linux_agent_path, "0.8.17", "linux_elf")
                with patch("app.main.RELEASE_VERSION", "0.8.17"):
                    hidden = client.post(
                        "/api/v1/agent-upgrades",
                        headers=headers,
                        json={"server_ids": [hidden_id], "reason": "A scoped manager cannot target a hidden server"},
                    )
                    self.assertEqual(hidden.status_code, 404, hidden.text)
                    visible = client.post(
                        "/api/v1/agent-upgrades",
                        headers=headers,
                        json={"server_ids": [visible_id], "reason": "Upgrade the one directly shared server"},
                    )
                    self.assertEqual(visible.status_code, 201, visible.text)
                    self.assertEqual([item["serverId"] for item in visible.json()["queued"]], [visible_id])
                    with SessionLocal() as db:
                        self.assertIsNone(db.execute(select(Job).where(Job.server_id == hidden_id, Job.action == "agent.upgrade")).scalar_one_or_none())
                        self.assertIsNotNone(db.execute(select(Job).where(Job.server_id == visible_id, Job.action == "agent.upgrade")).scalar_one_or_none())
                self.assertEqual(client.get("/api/v1/settings/agent-uninstall-protection", headers=headers).status_code, 403)
                denied = client.put(
                    "/api/v1/settings/agent-uninstall-protection",
                    headers=headers,
                    json={
                        "new_password": "Unauthorized-uninstall-secret!",
                        "confirm_password": "Unauthorized-uninstall-secret!",
                        "reason": "A custom role must not rotate the global uninstall password",
                    },
                )
                self.assertEqual(denied.status_code, 403, denied.text)
        finally:
            provenance_path.write_text(original_provenance, encoding="utf-8")
            with SessionLocal() as db:
                task_ids = db.execute(select(BulkTaskItem.bulk_task_id).where(BulkTaskItem.server_id.in_([visible_id, hidden_id]))).scalars().all()
                db.execute(delete(BulkTaskItem).where(BulkTaskItem.server_id.in_([visible_id, hidden_id])))
                if task_ids:
                    db.execute(delete(BulkTask).where(BulkTask.id.in_(task_ids)))
                db.execute(delete(ServerUserShare).where(ServerUserShare.user_id == user_id))
                db.execute(delete(Job).where(Job.server_id.in_([visible_id, hidden_id])))
                db.execute(delete(Server).where(Server.id.in_([visible_id, hidden_id])))
                db.execute(delete(User).where(User.id == user_id))
                db.execute(delete(PlatformRole).where(PlatformRole.name == role_name))
                db.commit()

    def test_windows_is_classified_as_windows(self):
        family, verification = classify_os(Inventory(hostname="win-01", os_family="windows", os_name="Microsoft Windows Server 2025", distribution_id="windows"))
        self.assertEqual((family, verification), ("windows", "verified"))

    def test_ubuntu_is_classified_as_linux(self):
        family, verification = classify_os(Inventory(hostname="ub-01", os_family="linux", os_name="Ubuntu 24.04.3 LTS", distribution_id="ubuntu"))
        self.assertEqual((family, verification), ("linux", "verified"))

    def test_oracle_linux_is_classified_as_linux(self):
        family, verification = classify_os(Inventory(hostname="ol-01", os_family="linux", os_name="Oracle Linux Server 8.10", distribution_id="ol"))
        self.assertEqual((family, verification), ("linux", "verified"))

    def test_guest_surface_is_minimal_and_api_documentation_is_disabled(self):
        with TestClient(app) as client:
            for path in ("/api/openapi.json", "/api/docs", "/api/docs/", "/api/redoc"):
                self.assertEqual(client.get(path).status_code, 404, path)

            status = client.get("/api/v1/setup/status")
            self.assertEqual(status.status_code, 200, status.text)
            self.assertEqual(
                set(status.json()),
                {"setupRequired", "databaseConnected", "setupTokenRequired", "status"},
            )
            self.assertTrue(status.json()["setupTokenRequired"])
            self.assertEqual(client.get("/livez").status_code, 200)
            self.assertEqual(client.get("/healthz").status_code, 200)
            self.assertEqual(client.get("/api/v1/agent-server-ca").status_code, 200)

            protected_paths = (
                "/api/v1/me",
                "/api/v1/users",
                "/api/v1/platform-groups",
                "/api/v1/remote-credentials",
                "/api/v1/roles",
                "/api/v1/settings/ldap",
                "/api/v1/settings/ldap/groups",
                "/api/v1/servers",
                "/api/v1/jobs",
                "/api/v1/audit",
                "/api/v1/sessions",
                "/api/v1/agent-packages/status",
                f"/api/v1/servers/{uuid.uuid4()}/jobs",
                f"/api/v1/sessions/{uuid.uuid4()}/recording",
            )
            for path in protected_paths:
                response = client.get(path)
                self.assertEqual(response.status_code, 401, path)
                self.assertEqual(response.headers.get("cache-control"), "no-store")
                self.assertEqual(response.headers.get("x-frame-options"), "DENY")
            self.assertEqual(client.post("/api/v1/settings/ldap/users/sync").status_code, 401)

    def test_remote_credentials_are_admin_managed_encrypted_and_selection_only(self):
        with TestClient(app) as client:
            admin_headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            viewer_id = str(uuid.uuid4())
            server_id = str(uuid.uuid4())
            clear_password = "Remote-only-secret-123!"
            with SessionLocal() as db:
                viewer = User(id=viewer_id, username=f"remote-operator-{viewer_id[:8]}", password_hash="!test", display_name="Remote Operator", role="operator", enabled=True)
                server = Server(id=server_id, name=f"remote-win-{server_id[:8]}", address="10.60.1.15", os_family="windows", os_name="Windows Server 2022", status="online")
                db.add_all([viewer, server])
                db.commit()
                viewer_headers = {"Authorization": f"Bearer {issue_jwt(viewer)}"}

            shared = client.put(f"/api/v1/servers/{server_id}/shares", headers=admin_headers, json={"user_ids": [viewer_id], "group_ids": []})
            self.assertEqual(shared.status_code, 200, shared.text)
            created = client.post(
                "/api/v1/remote-credentials",
                headers=admin_headers,
                json={"server_id": server_id, "protocol": "rdp", "label": "Tài khoản vận hành", "username": "svc-remote", "password": clear_password, "user_ids": [viewer_id]},
            )
            self.assertEqual(created.status_code, 201, created.text)
            credential_id = created.json()["id"]
            self.assertEqual(created.json()["username"], "svc-remote")
            self.assertNotIn("password", created.json())
            with SessionLocal() as db:
                stored = db.get(RemoteCredential, credential_id)
                self.assertIsNotNone(stored)
                self.assertNotEqual(stored.password_encrypted, clear_password)
                self.assertNotIn(clear_password, stored.password_encrypted)
                self.assertIsNotNone(db.get(RemoteCredentialUserShare, {"credential_id": credential_id, "user_id": viewer_id}))
                created_audit = db.execute(select(AuditEvent).where(AuditEvent.action == "remote_credential.create", AuditEvent.target == credential_id)).scalar_one()
                audit_text = json.dumps(created_audit.detail, ensure_ascii=False)
                self.assertNotIn(clear_password, audit_text)
                self.assertNotIn("svc-remote", audit_text)

            choices = client.get(f"/api/v1/servers/{server_id}/remote-credentials?protocol=rdp", headers=viewer_headers)
            self.assertEqual(choices.status_code, 200, choices.text)
            self.assertEqual(choices.json()["items"], [{"id": credential_id, "label": "Tài khoản vận hành", "protocol": "rdp"}])
            raw_launch = client.post("/api/v1/sessions/launch", headers=viewer_headers, json={"server_id": server_id, "protocol": "rdp", "username": "svc-remote", "password": clear_password, "width": 1280, "height": 720})
            self.assertEqual(raw_launch.status_code, 422, raw_launch.text)
            self.assertEqual(client.get("/api/v1/remote-credentials", headers=viewer_headers).status_code, 403)
            self.assertEqual(client.put(f"/api/v1/remote-credentials/{credential_id}", headers=viewer_headers, json={"label": "Changed", "username": "attacker", "password": "x", "user_ids": []}).status_code, 403)
            deleted = client.delete(f"/api/v1/remote-credentials/{credential_id}", headers=admin_headers)
            self.assertEqual(deleted.status_code, 200, deleted.text)
    def test_server_visibility_comes_only_from_direct_or_group_share(self):
        with TestClient(app) as client:
            admin_headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            viewer_id = str(uuid.uuid4())
            server_id = str(uuid.uuid4())
            with SessionLocal() as db:
                db.add(User(id=viewer_id, username=f"viewer-{viewer_id[:8]}", password_hash="!test", display_name="Scoped Viewer", role="viewer", enabled=True))
                db.add(Server(id=server_id, name=f"shared-{server_id[:8]}", os_family="linux", os_name="Oracle Linux", status="online"))
                db.commit()
                viewer = db.get(User, viewer_id)
                viewer_headers = {"Authorization": f"Bearer {issue_jwt(viewer)}"}
            self.assertEqual(client.get("/api/v1/servers", headers=viewer_headers).json()["items"], [])
            group_response = client.post("/api/v1/platform-groups", headers=admin_headers, json={"name": f"Ops {server_id[:8]}", "description": "Oracle operations", "member_ids": [viewer_id]})
            self.assertEqual(group_response.status_code, 201, group_response.text)
            share_response = client.put(f"/api/v1/servers/{server_id}/shares", headers=admin_headers, json={"user_ids": [], "group_ids": [group_response.json()["id"]]})
            self.assertEqual(share_response.status_code, 200, share_response.text)
            visible = client.get("/api/v1/servers", headers=viewer_headers)
            self.assertEqual([item["id"] for item in visible.json()["items"]], [server_id])
            self.assertEqual(client.get(f"/api/v1/servers/{server_id}", headers=viewer_headers).status_code, 200)
            deleted = client.request("DELETE", f"/api/v1/servers/{server_id}", headers=admin_headers, json={"confirmation": "DELETE", "reason": "Không còn sử dụng"})
            self.assertEqual(deleted.status_code, 200, deleted.text)
            self.assertEqual(client.get(f"/api/v1/servers/{server_id}", headers=viewer_headers).status_code, 404)

    def test_every_browser_api_route_is_public_by_design_or_has_authentication(self):
        public_routes = {
            "/livez",
            "/healthz",
            "/api/v1/setup/status",
            "/api/v1/setup/complete",
            "/api/v1/auth/login",
            "/api/v1/auth/mfa/verify",
            "/api/v1/agent-bootstrap/claim",
            "/api/v1/enroll",
            "/api/v1/agent-server-ca",
        }

        def depends_on_current_user(dependency) -> bool:
            return dependency.call is current_user or any(depends_on_current_user(child) for child in dependency.dependencies)

        unprotected: list[str] = []
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            if route.path in public_routes or route.path.startswith("/api/v1/agent/"):
                continue
            if not depends_on_current_user(route.dependant):
                unprotected.append(f"{','.join(sorted(route.methods or []))} {route.path}")
        self.assertEqual(unprotected, [])

    def test_password_login_is_rate_limited_by_identity_and_source(self):
        previous_account_limit = settings.auth_account_failures
        previous_ip_limit = settings.auth_ip_failures
        settings.auth_account_failures = 3
        settings.auth_ip_failures = 20
        source_headers = {"X-Forwarded-For": "198.51.100.45"}
        try:
            with TestClient(app) as client:
                for _ in range(3):
                    denied = client.post(
                        "/api/v1/auth/login",
                        headers=source_headers,
                        json={"username": f"missing-{uuid.uuid4().hex}", "password": "wrong-password"},
                    )
                    self.assertEqual(denied.status_code, 401, denied.text)
                identity = f"locked-{uuid.uuid4().hex}"
                for _ in range(3):
                    denied = client.post(
                        "/api/v1/auth/login",
                        headers=source_headers,
                        json={"username": identity, "password": "wrong-password"},
                    )
                    self.assertEqual(denied.status_code, 401, denied.text)
                throttled = client.post(
                    "/api/v1/auth/login",
                    headers=source_headers,
                    json={"username": identity, "password": "wrong-password"},
                )
                self.assertEqual(throttled.status_code, 429, throttled.text)
                self.assertGreater(int(throttled.headers["retry-after"]), 0)
        finally:
            settings.auth_account_failures = previous_account_limit
            settings.auth_ip_failures = previous_ip_limit
            with SessionLocal() as db:
                db.query(AuthThrottle).delete()
                db.commit()

    def test_logout_revokes_bearer_replay_and_browser_cookie_session(self):
        username = f"logout-{uuid.uuid4().hex[:8]}"
        password = "Logout-Test-Password-123!"
        with SessionLocal() as db:
            user = User(username=username, password_hash=password_hasher.hash(password), display_name="Logout Test", role="viewer", enabled=True)
            db.add(user)
            db.commit()
            user_id = user.id
        try:
            with TestClient(app, base_url="https://testserver") as client:
                login = client.post("/api/v1/auth/login", json={"username": username, "password": password})
                self.assertEqual(login.status_code, 200, login.text)
                secret = parse_qs(urlsplit(login.json()["provisioning_uri"]).query)["secret"][0]
                verified = client.post("/api/v1/auth/mfa/verify", headers={"X-Tram-Auth-Mode": "cookie"}, json={"challenge_token": login.json()["challenge_token"], "code": pyotp.TOTP(secret).now()})
                self.assertEqual(verified.status_code, 200, verified.text)
                self.assertNotIn("access_token", verified.json())
                bearer = client.cookies.get("tram_ops_session")
                self.assertTrue(bearer)
                cookie = verified.headers.get("set-cookie", "")
                self.assertIn("tram_ops_session=", cookie)
                self.assertIn("HttpOnly", cookie)
                self.assertIn("Secure", cookie)
                self.assertIn("SameSite=strict", cookie)
                self.assertEqual(client.get("/api/v1/me").status_code, 200)
                signed_out = client.post("/api/v1/auth/logout")
                self.assertEqual(signed_out.status_code, 200, signed_out.text)
                self.assertEqual(client.get("/api/v1/me").status_code, 401)
                replay = client.get("/api/v1/me", headers={"Authorization": f"Bearer {bearer}"})
                self.assertEqual(replay.status_code, 401, replay.text)
        finally:
            with SessionLocal() as db:
                db.execute(delete(RevokedSessionToken).where(RevokedSessionToken.user_id == user_id))
                credential = db.get(MFACredential, user_id)
                if credential:
                    db.delete(credential)
                user = db.get(User, user_id)
                if user:
                    db.delete(user)
                db.commit()

    def test_plaintext_ldap_configuration_is_rejected(self):
        with TestClient(app) as client:
            headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            response = client.put("/api/v1/settings/ldap", headers=headers, json={"enabled": False, "use_ssl": False})
            self.assertEqual(response.status_code, 422, response.text)

    def test_custom_role_and_per_user_ldap_role_are_enforced(self):
        role_name = f"ldapops_{uuid.uuid4().hex[:8]}"
        ldap_username = f"TEST\\ldap-{uuid.uuid4().hex[:8]}"
        with TestClient(app) as client:
            admin_headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            roles = client.get("/api/v1/roles", headers=admin_headers)
            self.assertEqual(roles.status_code, 200, roles.text)
            self.assertTrue({"admin", "operator", "viewer", "auditor"}.issubset({item["name"] for item in roles.json()["items"]}))
            self.assertIn("users.manage", {item["id"] for item in roles.json()["permissionCatalog"]})
            created_role = client.post("/api/v1/roles", headers=admin_headers, json={"name": role_name, "display_name": "LDAP Operations", "description": "Recording only", "permissions": ["servers.view", "recordings.view"]})
            self.assertEqual(created_role.status_code, 201, created_role.text)
            with SessionLocal() as db:
                ldap_user = User(username=ldap_username, password_hash="!LDAP", display_name="LDAP Test User", role="viewer")
                db.add(ldap_user)
                db.commit()
                ldap_user_id = ldap_user.id
                ldap_token = issue_jwt(ldap_user)
            updated = client.patch(f"/api/v1/users/{ldap_user_id}", headers=admin_headers, json={"role": role_name})
            self.assertEqual(updated.status_code, 200, updated.text)
            self.assertEqual(updated.json()["source"], "ldap")
            self.assertEqual(updated.json()["role"], role_name)
            password_change = client.patch(f"/api/v1/users/{ldap_user_id}", headers=admin_headers, json={"password": "not-allowed-password-123"})
            self.assertEqual(password_change.status_code, 422, password_change.text)
            ldap_headers = {"Authorization": f"Bearer {ldap_token}"}
            self.assertEqual(client.get("/api/v1/audit", headers=ldap_headers).status_code, 403)
            expanded_role = client.put(f"/api/v1/roles/{role_name}", headers=admin_headers, json={"display_name": "LDAP Operations", "description": "Recording and audit", "permissions": ["servers.view", "recordings.view", "audit.view"]})
            self.assertEqual(expanded_role.status_code, 200, expanded_role.text)
            self.assertEqual(client.get("/api/v1/audit", headers=ldap_headers).status_code, 200)
            self.assertEqual(client.delete(f"/api/v1/roles/{role_name}", headers=admin_headers).status_code, 409)
            self.assertEqual(client.patch(f"/api/v1/users/{ldap_user_id}", headers=admin_headers, json={"role": "viewer"}).status_code, 200)
            self.assertEqual(client.delete(f"/api/v1/roles/{role_name}", headers=admin_headers).status_code, 200)

    def test_allowed_ldap_group_members_are_synced_without_overwriting_assigned_roles(self):
        with TestClient(app):
            pass
        domain_label = f"AD{uuid.uuid4().hex[:8]}"
        config = {
            "base_dn": "DC=example,DC=test",
            "user_attribute": "sAMAccountName",
            "display_attribute": "displayName",
            "domain_label": domain_label,
            "default_role": "viewer",
            "allowed_group_dns": ["CN=Operations,OU=Groups,DC=example,DC=test"],
        }
        search_arguments: dict = {}

        def service_with(records: list[dict]):
            def paged_search(**kwargs):
                search_arguments.update(kwargs)
                return iter(records)

            return SimpleNamespace(extend=SimpleNamespace(standard=SimpleNamespace(paged_search=paged_search)))

        first_records = [
            {"type": "searchResEntry", "attributes": {"sAMAccountName": "alice", "displayName": "Alice AD"}},
            {"type": "searchResEntry", "attributes": {"sAMAccountName": "bob", "displayName": "Bob AD"}},
        ]
        try:
            with SessionLocal() as db:
                first = synchronize_ldap_users_from_connection(db, config, service_with(first_records))
                db.commit()
                self.assertEqual(first, {"scanned": 2, "created": 2, "updated": 0, "unchanged": 0, "conflicts": 0, "skipped": 0})
                self.assertIn("1.2.840.113556.1.4.1941", search_arguments["search_filter"])
                alice = db.execute(select(User).where(User.username == f"{domain_label}\\alice")).scalar_one()
                bob = db.execute(select(User).where(User.username == f"{domain_label}\\bob")).scalar_one()
                self.assertEqual((alice.password_hash, bob.password_hash), ("!LDAP", "!LDAP"))
                alice.role = "auditor"
                alice.enabled = False
                db.commit()

            second_records = [
                {"type": "searchResEntry", "attributes": {"sAMAccountName": "ALICE", "displayName": "Alice Renamed"}},
                {"type": "searchResEntry", "attributes": {"sAMAccountName": "bob", "displayName": "Bob AD"}},
            ]
            with SessionLocal() as db:
                second = synchronize_ldap_users_from_connection(db, config, service_with(second_records))
                db.commit()
                self.assertEqual(second, {"scanned": 2, "created": 0, "updated": 1, "unchanged": 1, "conflicts": 0, "skipped": 0})
                alice = db.execute(select(User).where(User.username == f"{domain_label}\\alice")).scalar_one()
                self.assertEqual(alice.display_name, "Alice Renamed")
                self.assertEqual(alice.role, "auditor")
                self.assertFalse(alice.enabled)
        finally:
            with SessionLocal() as db:
                for user in db.execute(select(User).where(User.username.like(f"{domain_label}\\%"))).scalars().all():
                    db.delete(user)
                db.commit()

    def test_viewer_can_load_its_allowed_workspace_without_identity_admin_access(self):
        with SessionLocal() as db:
            viewer = User(
                username=f"viewer-{uuid.uuid4().hex[:8]}",
                password_hash="unused-test-hash",
                display_name="Read Only Viewer",
                role="viewer",
            )
            db.add(viewer)
            db.commit()
            viewer_id = viewer.id
            viewer_headers = {"Authorization": f"Bearer {issue_jwt(viewer)}"}
        try:
            with TestClient(app) as client:
                profile = client.get("/api/v1/me", headers=viewer_headers)
                self.assertEqual(profile.status_code, 200, profile.text)
                self.assertEqual(profile.json()["role"], "viewer")
                self.assertEqual(set(profile.json()["permissions"]), {"logs.view", "resources.view", "servers.view"})
                self.assertEqual(client.get("/api/v1/servers", headers=viewer_headers).status_code, 200)
                self.assertEqual(client.get("/api/v1/users", headers=viewer_headers).status_code, 403)
                self.assertEqual(client.get("/api/v1/settings/ldap", headers=viewer_headers).status_code, 403)
                self.assertEqual(client.get("/api/v1/roles", headers=viewer_headers).status_code, 403)
                with SessionLocal() as db:
                    denial = db.execute(select(AuditEvent).where(AuditEvent.actor == viewer.username, AuditEvent.action == "security.authorization.denied").order_by(AuditEvent.occurred_at.desc())).scalars().first()
                    self.assertIsNotNone(denial)
                    self.assertEqual(denial.result, "denied")
        finally:
            with SessionLocal() as db:
                stored = db.get(User, viewer_id)
                if stored:
                    db.delete(stored)
                    db.commit()

    def test_self_service_profile_password_and_admin_mfa_reset(self):
        username = f"self-service-{uuid.uuid4().hex[:8]}"
        old_password = "Old-Self-Service-Password-123!"
        new_password = "New-Self-Service-Password-456!"
        with TestClient(app) as client:
            admin_headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            with SessionLocal() as db:
                user = User(username=username, password_hash=password_hasher.hash(old_password), display_name="Self Service", role="viewer", enabled=True)
                db.add(user)
                db.flush()
                db.add(MFACredential(user_id=user.id, secret_encrypted="test-encrypted-secret", enrolled=True, last_counter=4))
                db.commit()
                user_id = user.id
                user_headers = {"Authorization": f"Bearer {issue_jwt(user)}"}
            try:
                profile = client.get("/api/v1/me", headers=user_headers)
                self.assertEqual(profile.status_code, 200, profile.text)
                self.assertEqual(profile.json()["source"], "local")
                self.assertTrue(profile.json()["mfaEnrolled"])

                role_injection = client.patch("/api/v1/me/profile", headers=user_headers, json={"display_name": "Injected", "role": "admin"})
                self.assertEqual(role_injection.status_code, 422, role_injection.text)
                updated = client.patch("/api/v1/me/profile", headers=user_headers, json={"display_name": "Tên hiển thị mới"})
                self.assertEqual(updated.status_code, 200, updated.text)
                self.assertEqual(updated.json()["displayName"], "Tên hiển thị mới")
                self.assertEqual(updated.json()["role"], "viewer")

                wrong_password = client.post("/api/v1/me/password", headers=user_headers, json={"current_password": "incorrect-password", "new_password": new_password})
                self.assertEqual(wrong_password.status_code, 401, wrong_password.text)
                changed = client.post("/api/v1/me/password", headers=user_headers, json={"current_password": old_password, "new_password": new_password})
                self.assertEqual(changed.status_code, 200, changed.text)

                denied_reset = client.delete(f"/api/v1/users/{user_id}/mfa", headers=user_headers)
                self.assertEqual(denied_reset.status_code, 403, denied_reset.text)
                reset = client.delete(f"/api/v1/users/{user_id}/mfa", headers=admin_headers)
                self.assertEqual(reset.status_code, 200, reset.text)
                self.assertTrue(reset.json()["wasEnrolled"])

                with SessionLocal() as db:
                    persisted = db.get(User, user_id)
                    self.assertEqual((persisted.display_name, persisted.role), ("Tên hiển thị mới", "viewer"))
                    self.assertTrue(password_hasher.verify(persisted.password_hash, new_password))
                    self.assertIsNone(db.get(MFACredential, user_id))
                    actions = set(db.execute(select(AuditEvent.action).where(AuditEvent.target == user_id)).scalars().all())
                    self.assertTrue({"identity.self.profile.update", "identity.self.password.change", "identity.mfa.reset"}.issubset(actions))

                self.assertEqual(client.post("/api/v1/auth/login", json={"username": username, "password": old_password}).status_code, 401)
                next_login = client.post("/api/v1/auth/login", json={"username": username, "password": new_password})
                self.assertEqual(next_login.status_code, 200, next_login.text)
                self.assertTrue(next_login.json()["setup_required"])
                self.assertTrue(next_login.json()["qr_svg"].startswith("data:image/svg+xml;base64,"))
            finally:
                with SessionLocal() as db:
                    db.query(MFACredential).filter(MFACredential.user_id == user_id).delete()
                    db.query(User).filter(User.id == user_id).delete()
                    db.query(AuthThrottle).delete()
                    db.commit()

    def test_viewer_first_login_receives_an_mfa_qr(self):
        username = f"viewer-mfa-{uuid.uuid4().hex[:8]}"
        password = "Viewer-MFA-Test-Password-123!"
        user_id = ""
        try:
            with TestClient(app) as client:
                admin_headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
                created = client.post("/api/v1/users", headers=admin_headers, json={
                    "username": username,
                    "display_name": "Viewer MFA Test",
                    "password": password,
                    "role": "viewer",
                })
                self.assertEqual(created.status_code, 201, created.text)
                user_id = created.json()["id"]
                login = client.post("/api/v1/auth/login", json={"username": username, "password": password, "source": "local"})
                self.assertEqual(login.status_code, 200, login.text)
                payload = login.json()
                self.assertTrue(payload["setup_required"])
                self.assertEqual(payload["user"]["role"], "viewer")
                self.assertTrue(payload["qr_svg"].startswith("data:image/svg+xml;base64,"))
        finally:
            if user_id:
                with SessionLocal() as db:
                    stored = db.get(User, user_id)
                    if stored:
                        db.delete(stored)
                        db.commit()

    def test_resource_mutations_have_matching_automatic_refreshes(self):
        self.assertEqual(AUTO_REFRESH_ACTIONS["storage.extend"], ("storage.list",))
        self.assertEqual(AUTO_REFRESH_ACTIONS["storage.shrink"], ("storage.list",))
        self.assertEqual(AUTO_REFRESH_ACTIONS["service.restart"], ("service.list",))
        self.assertEqual(AUTO_REFRESH_ACTIONS["user.update"], ("user.list", "group.list"))
        self.assertEqual(AUTO_REFRESH_ACTIONS["process.kill"], ("process.list",))
        self.assertEqual(AUTO_REFRESH_ACTIONS["patch.install"], ("patch.scan",))
        self.assertEqual(AUTO_REFRESH_ACTIONS["firewall.rule.add.auto"], ("firewall.list",))

    def test_bulk_user_task_persists_one_encrypted_job_per_target(self):
        server_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
        with SessionLocal() as db:
            db.add_all([
                Server(id=server_ids[0], name="bulk-win-01", os_family="windows", os_name="Windows Server 2022"),
                Server(id=server_ids[1], name="bulk-win-02", os_family="windows", os_name="Windows Server 2025"),
            ])
            db.commit()
        with TestClient(app) as client:
            headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            password = "Bulk-Test-Password-123!"
            response = client.post("/api/v1/bulk-tasks", headers=headers, json={
                "os_family": "windows",
                "server_ids": server_ids,
                "action": "user.create",
                "parameters": {"username": "batchops", "password": password, "is_admin": True},
                "reason": "CHG-2048 create the operations account",
            })
            self.assertEqual(response.status_code, 201, response.text)
            payload = response.json()
            self.assertEqual(payload["targetCount"], 2)
            self.assertEqual(payload["summary"], {"username": "batchops", "isAdmin": True})
            self.assertEqual({item["serverId"] for item in payload["items"]}, set(server_ids))
            listed = client.get("/api/v1/bulk-tasks?os_family=windows", headers=headers)
            self.assertEqual(listed.status_code, 200, listed.text)
            self.assertTrue(any(item["id"] == payload["id"] for item in listed.json()["items"]))
        with SessionLocal() as db:
            task = db.get(BulkTask, payload["id"])
            self.assertIsNotNone(task)
            items = db.execute(select(BulkTaskItem).where(BulkTaskItem.bulk_task_id == payload["id"])).scalars().all()
            self.assertEqual(len(items), 2)
            jobs = [db.get(Job, item.job_id) for item in items]
            self.assertTrue(all(job and job.action == "user.create" and job.status == "queued" for job in jobs))
            self.assertTrue(all(password not in json.dumps(job.parameters) for job in jobs if job))

    def test_bulk_update_catalog_requires_same_platform_and_pins_each_server_revision(self):
        server_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
        common_id = "11111111-2222-3333-4444-555555555555"
        with SessionLocal() as db:
            for index, server_id in enumerate(server_ids):
                db.add(Server(id=server_id, name=f"bulk-patch-{index}", os_family="windows", os_name="Microsoft Windows Server 2022 Standard", os_version="10.0.20348", architecture="AMD64"))
                db.add(Job(
                    server_id=server_id,
                    action="patch.scan",
                    status="succeeded",
                    risk="low",
                    reason="automatic inventory",
                    created_by="system",
                    output=json.dumps({
                        "platform": "windows",
                        "updates": [
                            {"id": common_id, "revision": index + 4, "name": "2026-08 Cumulative Update", "version": "KB5099999", "repository": "WSUS", "severity": "security"},
                            {"id": f"host-only-{index}", "revision": 1, "name": f"Only host {index}", "version": f"KB500000{index}"},
                        ],
                        "diagnostics": {"currentScanComplete": True},
                    }),
                ))
            db.commit()
        with TestClient(app) as client:
            headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            catalog = client.post("/api/v1/bulk-update/catalog", headers=headers, json={"os_family": "windows", "server_ids": server_ids})
            self.assertEqual(catalog.status_code, 200, catalog.text)
            self.assertTrue(catalog.json()["ready"])
            self.assertEqual([(item["id"], item["version"]) for item in catalog.json()["updates"]], [(common_id, "KB5099999")])
            created = client.post("/api/v1/bulk-tasks", headers=headers, json={
                "os_family": "windows",
                "server_ids": server_ids,
                "action": "patch.install",
                "parameters": {"updates": [{"id": common_id, "version": "KB5099999"}]},
                "reason": "CHG-4096 install the common cumulative update",
            })
            self.assertEqual(created.status_code, 201, created.text)
        with SessionLocal() as db:
            jobs = db.execute(select(Job).where(Job.server_id.in_(server_ids), Job.action == "patch.install").order_by(Job.server_id)).scalars().all()
            self.assertEqual(len(jobs), 2)
            self.assertEqual({job.parameters["updates"][0]["revision"] for job in jobs}, {4, 5})
            self.assertTrue(all(job.parameters["updates"][0]["id"] == common_id for job in jobs))

    def test_bulk_ubuntu_update_source_accepts_pulp_distribution_urls(self):
        server_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
        with TestClient(app):
            pass
        repository_urls = {
            "noble": "http://pulp.internal/pulp/content/ubuntu/24.04/noble",
            "noble-updates": "http://pulp.internal/pulp/content/ubuntu/24.04/noble-updates",
            "noble-security": "http://pulp.internal/pulp/content/ubuntu/24.04/noble-security",
        }
        with SessionLocal() as db:
            for index, server_id in enumerate(server_ids):
                db.add(Server(
                    id=server_id,
                    name=f"bulk-ubuntu-{index}",
                    address=f"10.81.0.{index + 10}",
                    os_family="linux",
                    os_name="Ubuntu 24.04 LTS",
                    os_version="24.04.2",
                    distribution_id="ubuntu",
                    architecture="x86_64",
                ))
                db.add(Job(
                    server_id=server_id,
                    action="patch.source.read",
                    status="succeeded",
                    risk="low",
                    reason="read current sources",
                    created_by="system",
                    output=json.dumps({"platform": "ubuntu", "mode": "custom", "repositoryUrls": repository_urls}),
                ))
            db.commit()
        with TestClient(app) as client:
            headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            catalog = client.post("/api/v1/bulk-update-sources/catalog", headers=headers, json={"os_family": "linux", "server_ids": server_ids})
            self.assertEqual(catalog.status_code, 200, catalog.text)
            body = catalog.json()
            self.assertTrue(body["ready"])
            self.assertEqual(body["profile"], "ubuntu-24.04")
            rows = {item["id"]: item for item in body["repositories"]}
            self.assertEqual(rows["noble-security"]["currentUrls"], [repository_urls["noble-security"]])
            self.assertTrue(rows["noble-backports"]["optional"])

            repositories = [{"id": suite, "base_url": url} for suite, url in repository_urls.items()]
            created = client.post("/api/v1/bulk-tasks", headers=headers, json={
                "os_family": "linux",
                "server_ids": server_ids,
                "action": "patch.source.configure",
                "parameters": {"mode": "custom", "repositories": repositories},
                "reason": "CHG-8200 switch Ubuntu hosts to Pulp distributions",
            })
            self.assertEqual(created.status_code, 201, created.text)
            self.assertEqual(created.json()["targetCount"], 2)
        with SessionLocal() as db:
            jobs = db.execute(select(Job).where(Job.server_id.in_(server_ids), Job.action == "patch.source.configure").order_by(Job.server_id)).scalars().all()
            self.assertEqual(len(jobs), 2)
            self.assertTrue(all(job.parameters["repositories"] == repositories for job in jobs))

    def test_update_source_profile_settings_persist_and_validate_by_os(self):
        key = "update_source_profile:ubuntu-24.04"
        with SessionLocal() as db:
            db.execute(delete(SystemSetting).where(SystemSetting.key == key))
            db.execute(delete(AuditEvent).where(AuditEvent.action == "settings.update_source_profile.update", AuditEvent.target == "ubuntu-24.04"))
            db.commit()
        try:
            with TestClient(app) as client:
                self.assertEqual(client.get("/api/v1/settings/update-sources").status_code, 401)
                headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
                before = client.get("/api/v1/settings/update-sources", headers=headers)
                self.assertEqual(before.status_code, 200, before.text)
                self.assertEqual(len(before.json()["items"]), 5)
                ubuntu_before = next(item for item in before.json()["items"] if item["profile"] == "ubuntu-24.04")
                self.assertFalse(ubuntu_before["saved"])

                repositories = [
                    {"id": "noble", "base_url": "http://10.64.70.15/pulp/content/ubuntu/24.04/noble/"},
                    {"id": "noble-updates", "base_url": "http://10.64.70.15/pulp/content/ubuntu/24.04/noble-updates/"},
                    {"id": "noble-security", "base_url": "http://10.64.70.15/pulp/content/ubuntu/24.04/noble-security/"},
                ]
                saved = client.put("/api/v1/settings/update-sources/ubuntu-24.04", headers=headers, json={"mode": "custom", "repositories": repositories})
                self.assertEqual(saved.status_code, 200, saved.text)
                self.assertTrue(saved.json()["saved"])
                self.assertEqual(saved.json()["repositories"][0], {"id": "noble", "baseUrl": repositories[0]["base_url"].rstrip("/")})

                after = client.get("/api/v1/settings/update-sources", headers=headers)
                ubuntu_after = next(item for item in after.json()["items"] if item["profile"] == "ubuntu-24.04")
                self.assertEqual(ubuntu_after["mode"], "custom")
                self.assertEqual(len(ubuntu_after["repositories"]), 3)

                invalid = client.put("/api/v1/settings/update-sources/ubuntu-24.04", headers=headers, json={
                    "mode": "custom",
                    "repositories": [
                        {"id": "jammy", "base_url": "https://repo.internal/jammy"},
                        {"id": "jammy-updates", "base_url": "https://repo.internal/jammy-updates"},
                        {"id": "jammy-security", "base_url": "https://repo.internal/jammy-security"},
                    ],
                })
                self.assertEqual(invalid.status_code, 422, invalid.text)
            with SessionLocal() as db:
                setting = db.get(SystemSetting, key)
                self.assertIsNotNone(setting)
                self.assertEqual(json.loads(setting.value)["mode"], "custom")
                event = db.execute(select(AuditEvent).where(AuditEvent.action == "settings.update_source_profile.update", AuditEvent.target == "ubuntu-24.04")).scalars().first()
                self.assertIsNotNone(event)
        finally:
            with SessionLocal() as db:
                db.execute(delete(SystemSetting).where(SystemSetting.key == key))
                db.commit()

    def test_bulk_oracle_update_source_uses_real_repository_ids_per_server(self):
        server_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
        with TestClient(app):
            pass
        with SessionLocal() as db:
            for index, server_id in enumerate(server_ids):
                db.add(Server(
                    id=server_id,
                    name=f"bulk-oracle-{index}",
                    address=f"10.80.0.{index + 10}",
                    os_family="linux",
                    os_name="Oracle Linux Server",
                    os_version="8.10",
                    distribution_id="ol",
                    architecture="x86_64",
                ))
                repositories = [
                    {"id": "ol8_baseos_latest", "url": "https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64", "enabled": True},
                ]
                if index == 0:
                    repositories.append({"id": "ol8_appstream", "url": "https://yum.oracle.com/repo/OracleLinux/OL8/appstream/x86_64", "enabled": True})
                db.add(Job(
                    server_id=server_id,
                    action="patch.source.read",
                    status="succeeded",
                    risk="low",
                    reason="read current sources",
                    created_by="system",
                    output=json.dumps({"platform": "oracle", "mode": "default", "repositories": repositories}),
                ))
            db.commit()
        with TestClient(app) as client:
            headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            catalog = client.post("/api/v1/bulk-update-sources/catalog", headers=headers, json={"os_family": "linux", "server_ids": server_ids})
            self.assertEqual(catalog.status_code, 200, catalog.text)
            body = catalog.json()
            self.assertTrue(body["ready"])
            self.assertEqual(body["profile"], "oracle-8")
            self.assertEqual({item["id"]: item["requiredOn"] for item in body["repositories"]}, {"ol8_appstream": 1, "ol8_baseos_latest": 2})

            created = client.post("/api/v1/bulk-tasks", headers=headers, json={
                "os_family": "linux",
                "server_ids": server_ids,
                "action": "patch.source.configure",
                "parameters": {
                    "mode": "custom",
                    "repositories": [
                        {"id": "ol8_baseos_latest", "base_url": "https://repo.internal/ol8/baseos/$basearch"},
                        {"id": "ol8_appstream", "base_url": "https://repo.internal/ol8/appstream/$basearch"},
                    ],
                },
                "reason": "CHG-8192 switch Oracle hosts to the managed mirror",
            })
            self.assertEqual(created.status_code, 201, created.text)
            self.assertEqual(created.json()["targetCount"], 2)
        with SessionLocal() as db:
            jobs = db.execute(select(Job).where(Job.server_id.in_(server_ids), Job.action == "patch.source.configure").order_by(Job.server_id)).scalars().all()
            self.assertEqual(len(jobs), 2)
            repositories_by_server = {job.server_id: {item["id"] for item in job.parameters["repositories"]} for job in jobs}
            self.assertEqual(repositories_by_server[server_ids[0]], {"ol8_baseos_latest", "ol8_appstream"})
            self.assertEqual(repositories_by_server[server_ids[1]], {"ol8_baseos_latest"})

    def test_common_firewall_payload_rejects_unknown_commands_and_wrong_family(self):
        valid = {"name": "SSH from jump", "direction": "in", "action": "allow", "protocol": "tcp", "local_port": 22, "remote_port": "any", "source": "10.64.83.172/32", "destination": "any", "family": "ipv4"}
        validate_firewall_job_parameters("firewall.rule.add.auto", valid)
        with self.assertRaises(HTTPException):
            validate_firewall_job_parameters("firewall.rule.add.auto", {**valid, "command": "iptables -F"})
        with self.assertRaises(HTTPException):
            validate_firewall_job_parameters("firewall.rule.add.auto", {**valid, "source": "2001:db8::/64"})

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
            filtered = client.get("/api/v1/audit", params={"search": "recent-user", "result": "success", "action": "test.recent"}, headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(filtered.status_code, 200, filtered.text)
            self.assertEqual([item["id"] for item in filtered.json()["items"]], [recent_id])

    def test_storage_actions_must_match_the_server_os(self):
        windows = Server(id=str(uuid.uuid4()), name="win", os_family="windows", os_name="Windows Server")
        linux = Server(id=str(uuid.uuid4()), name="linux", os_family="linux", os_name="Ubuntu")
        validate_job_parameters("storage.extend", {"kind": "windows_partition", "disk_number": 0, "partition_number": 2, "add_bytes": 1024**3}, windows)
        validate_job_parameters("storage.shrink", {"kind": "windows_partition", "disk_number": 0, "partition_number": 2, "shrink_bytes": 1024**3}, windows)
        validate_job_parameters("storage.create", {"kind": "linux_lv", "vg_name": "vg0", "name": "data", "size_bytes": 1024**3}, linux)
        validate_job_parameters("storage.extend", {"kind": "linux_lv", "path": "/dev/vg0/data", "add_bytes": 1024**3}, linux)
        validate_job_parameters("storage.delete", {"kind": "linux_lv", "path": "/dev/vg0/data"}, linux)
        validate_job_parameters("storage.create", {"kind": "linux_volume", "source_kind": "existing_vg", "vg_name": "vg0", "name": "data", "size_bytes": 1024**3, "filesystem": "ext4", "mount_point": "/data/app"}, linux)
        validate_job_parameters("storage.create", {"kind": "linux_volume", "source_kind": "empty_partition", "vg_name": "data-vg", "name": "data", "device": "/dev/sdb1", "size_bytes": 1024**3, "filesystem": "xfs", "mount_point": "/srv/data"}, linux)
        validate_job_parameters("storage.create", {"kind": "linux_volume", "source_kind": "free_region", "vg_name": "data-vg", "name": "data", "disk": "/dev/sdb", "start_bytes": 1024**2, "source_size_bytes": 2 * 1024**3, "size_bytes": 1024**3, "filesystem": "ext4", "mount_point": "/data"}, linux)
        with self.assertRaisesRegex(Exception, "operating system"):
            validate_job_parameters("storage.extend", {"kind": "linux_partition", "path": "/dev/sda1", "add_bytes": 1024**3}, windows)
        with self.assertRaisesRegex(Exception, "operating system"):
            validate_job_parameters("storage.shrink", {"kind": "windows_partition", "disk_number": 0, "partition_number": 2, "shrink_bytes": 1024**3}, linux)
        with self.assertRaisesRegex(Exception, "operating system"):
            validate_job_parameters("storage.extend", {"kind": "linux_vg", "name": "vg0", "add_bytes": 1024**3}, linux)
        with self.assertRaisesRegex(Exception, "unsupported"):
            validate_job_parameters("storage.delete", {"kind": "linux_lv", "path": "/dev/vg0/data", "command": "rm -rf /"}, linux)
        with self.assertRaisesRegex(Exception, "source"):
            validate_job_parameters("storage.create", {"kind": "linux_volume", "source_kind": "free_region", "vg_name": "vg0", "name": "data", "size_bytes": 1024**3, "filesystem": "ext4", "mount_point": "/data/app"}, linux)
        with self.assertRaisesRegex(Exception, "mount point"):
            validate_job_parameters("storage.create", {"kind": "linux_volume", "source_kind": "existing_vg", "vg_name": "vg0", "name": "data", "size_bytes": 1024**3, "filesystem": "ext4", "mount_point": "/etc/data"}, linux)
        with self.assertRaisesRegex(Exception, "mount point"):
            validate_job_parameters("storage.create", {"kind": "linux_volume", "source_kind": "existing_vg", "vg_name": "vg0", "name": "data", "size_bytes": 1024**3, "filesystem": "ext4", "mount_point": "/data/../etc"}, linux)
        with self.assertRaisesRegex(Exception, "positive byte"):
            validate_job_parameters("storage.create", {"kind": "linux_volume", "source_kind": "free_region", "vg_name": "vg0", "name": "data", "disk": "/dev/sdb", "start_bytes": 1024**2, "source_size_bytes": 0, "size_bytes": 1024**3, "filesystem": "ext4", "mount_point": "/data/app"}, linux)
        with self.assertRaisesRegex(Exception, "name is invalid"):
            validate_job_parameters("storage.create", {"kind": "linux_volume", "source_kind": "existing_vg", "vg_name": "--config", "name": "data", "size_bytes": 1024**3, "filesystem": "ext4", "mount_point": "/data/app"}, linux)

    def test_update_source_configuration_is_os_scoped_and_validated(self):
        windows = Server(id=str(uuid.uuid4()), name="win", os_family="windows", os_name="Windows Server 2022", os_version="10.0.20348")
        ubuntu = Server(id=str(uuid.uuid4()), name="ubuntu", os_family="linux", os_name="Ubuntu", os_version="24.04.3", distribution_id="ubuntu")
        oracle = Server(id=str(uuid.uuid4()), name="oracle", os_family="linux", os_name="Oracle Linux Server", os_version="8.10", distribution_id="ol")

        validate_job_parameters("patch.source.configure", {"mode": "internet", "wsus_url": ""}, windows)
        validate_job_parameters("patch.source.configure", {"mode": "wsus", "wsus_url": "http://wsus.internal:8530"}, windows)
        validate_job_parameters("patch.source.configure", {"mode": "custom", "repository_url": "https://repo.internal/ubuntu"}, ubuntu)
        validate_job_parameters("patch.source.configure", {"mode": "custom", "repositories": [
            {"id": "noble", "base_url": "http://pulp.internal/ubuntu/noble"},
            {"id": "noble-updates", "base_url": "http://pulp.internal/ubuntu/noble-updates"},
            {"id": "noble-security", "base_url": "http://pulp.internal/ubuntu/noble-security"},
        ]}, ubuntu)
        validate_job_parameters("patch.source.configure", {"mode": "custom", "repositories": [{"id": "ol8_baseos_latest", "base_url": "https://repo.internal/ol8/baseos/$basearch"}]}, oracle)
        with self.assertRaisesRegex(Exception, "Tham số cấu hình nguồn cập nhật Ubuntu không hợp lệ"):
            validate_job_parameters("patch.source.configure", {"mode": "custom", "wsus_url": "", "repositories": [
                {"id": "noble", "base_url": "http://pulp.internal/ubuntu/noble"},
                {"id": "noble-updates", "base_url": "http://pulp.internal/ubuntu/noble-updates"},
                {"id": "noble-security", "base_url": "http://pulp.internal/ubuntu/noble-security"},
            ]}, ubuntu)
        self.assertEqual(AUTO_REFRESH_ACTIONS["patch.source.configure"], ("patch.source.read", "patch.scan"))

        invalid_payloads = [
            (windows, {"mode": "wsus", "wsus_url": "https://user:secret@wsus.internal"}),
            (ubuntu, {"mode": "custom", "repository_url": "file:///srv/ubuntu"}),
            (ubuntu, {"mode": "custom", "repositories": [
                {"id": "noble", "base_url": "http://pulp.internal/ubuntu/noble"},
                {"id": "noble-updates", "base_url": "http://pulp.internal/ubuntu/noble-updates"},
            ]}),
            (ubuntu, {"mode": "custom", "repositories": [
                {"id": "jammy", "base_url": "http://pulp.internal/ubuntu/jammy"},
                {"id": "jammy-updates", "base_url": "http://pulp.internal/ubuntu/jammy-updates"},
                {"id": "jammy-security", "base_url": "http://pulp.internal/ubuntu/jammy-security"},
            ]}),
            (oracle, {"mode": "custom", "repositories": [{"id": "docker-ce-stable", "base_url": "https://repo.internal/docker"}]}),
        ]
        for server, parameters in invalid_payloads:
            with self.subTest(server=server.name), self.assertRaises(Exception):
                validate_job_parameters("patch.source.configure", parameters, server)

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
            self.assertEqual(listed_failure["serverName"], "firewall-refresh")
            self.assertEqual(listed_failure["serverAddress"], "10.30.1.70")
            with SessionLocal() as db:
                refreshes = db.query(Job).filter(Job.server_id == agent_id, Job.action == "firewall.list", Job.reason.like("Tự động quét lại sau%")).all()
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
                    json={"label": "missing-ca", "os_family": "linux", "linux_profile": "ubuntu-24.04", "expires_minutes": 15},
                )
                self.assertEqual(package.status_code, 503, package.text)
                self.assertIn("Chứng thư bảo mật của kênh Agent", package.json()["detail"])
                self.assertNotIn("caddy", package.json()["detail"].lower())

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
            with SessionLocal() as db:
                initial_actions = db.execute(select(Job.action).where(Job.server_id == agent_id).order_by(Job.created_at)).scalars().all()
                self.assertEqual(tuple(initial_actions), INITIAL_SERVER_SCAN_ACTIONS)

            issued = x509.load_pem_x509_certificate(enroll.json()["certificate"].encode())
            checkin_payload = {"agent_id": agent_id, "agent_version": "0.1.0", "active_job_ids": [], "inventory": None, "metrics": {"cpu_percent": 12, "memory_percent": 40, "disk_percent": 30, "uptime_seconds": 3600, "pending_updates": 2, "services_running": 80, "alerts": 0}}
            checkin_body, checkin_headers = signed_agent_request(agent_key, issued, "/api/v1/agent/checkin", checkin_payload)
            checkin = client.post("/api/v1/agent/checkin", headers=checkin_headers, content=checkin_body)
            self.assertEqual(checkin.status_code, 200, checkin.text)
            self.assertEqual(checkin.json()["checkin_interval_seconds"], 5)
            self.assertEqual(checkin.json()["max_concurrent_jobs"], 4)
            self.assertEqual(len(checkin.json()["jobs"]), 4)
            checkin_payload["active_job_ids"] = [job["id"] for job in checkin.json()["jobs"]]
            checkin_payload["active_job_id"] = checkin_payload["active_job_ids"][0]
            active_body, active_headers = signed_agent_request(agent_key, issued, "/api/v1/agent/checkin", checkin_payload)
            active_checkin = client.post("/api/v1/agent/checkin", headers=active_headers, content=active_body)
            self.assertEqual(active_checkin.status_code, 200, active_checkin.text)
            self.assertEqual(active_checkin.json()["jobs"], [])
            checkin_payload.pop("active_job_id")
            checkin_payload["active_job_ids"] = []

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
        write_artifact_provenance(
            fake_msi,
            (Path(settings.agent_assets_root) / "VERSION").read_text(encoding="ascii").strip(),
            "windows_msi",
        )
        settings.windows_agent_msi = str(fake_msi)

        with TestClient(app) as client:
            headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
            status = client.get("/api/v1/agent-packages/status", headers=headers)
            self.assertEqual(status.status_code, 200, status.text)
            self.assertEqual(status.json()["dashboardUrl"], "https://ops.company.example")
            self.assertEqual(status.json()["agentVersion"], (Path(settings.agent_assets_root) / "VERSION").read_text(encoding="ascii").strip())
            self.assertEqual(app.version, status.json()["agentVersion"])
            self.assertTrue(status.json()["windowsMsiAvailable"])
            self.assertTrue(all(status.json()["linuxOfflineProfiles"].values()))
            self.assertTrue(status.json()["agentTlsCaAvailable"])

            missing_profile = client.post(
                "/api/v1/agent-packages",
                headers=headers,
                json={"label": "missing-profile", "os_family": "linux", "expires_minutes": 15},
            )
            self.assertEqual(missing_profile.status_code, 422, missing_profile.text)
            self.assertIn("phiên bản Linux", missing_profile.json()["detail"])
            linux_package = client.post(
                "/api/v1/agent-packages",
                headers=headers,
                json={"label": "ubuntu-prod-01", "os_family": "linux", "linux_profile": "ubuntu-24.04", "expires_minutes": 15},
            )
            self.assertEqual(linux_package.status_code, 200, linux_package.text)
            self.assertIn("TramAgent-Linux-ubuntu-24.04-ubuntu-prod-01.run", linux_package.headers["content-disposition"])
            marker = b"__TRAM_AGENT_ARCHIVE__\n"
            archive_bytes = linux_package.content.split(marker, 1)[1]
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
                self.assertEqual(archive.extractfile("VERSION").read().decode().strip(), app.version)
                self.assertGreater(len(archive.extractfile("linux/x86_64/tram-agent").read()), 1024 * 512)
                self.assertTrue(all(member.mtime >= 1_704_067_200 for member in archive.getmembers()))
                self.assertNotIn("requirements.txt", archive.getnames())
                self.assertNotIn("tram_agent.py", archive.getnames())
                self.assertEqual(archive.extractfile("linux-profile").read().decode().strip(), "ubuntu-24.04")
                offline_content = archive.extractfile("offline-dependencies.tar.gz").read()
                checksum = archive.extractfile("offline-dependencies.sha256").read().decode().split()[0]
                self.assertEqual(hashlib.sha256(offline_content).hexdigest(), checksum)
                with tarfile.open(fileobj=io.BytesIO(offline_content), mode="r:gz") as offline_archive:
                    self.assertIn("manifest.json", offline_archive.getnames())
                    self.assertTrue(any(name.endswith(".deb") for name in offline_archive.getnames()))
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
            with SessionLocal() as db:
                package = db.get(AgentBootstrapPackage, bootstrap["package_id"])
                initial_jobs = db.execute(select(Job).where(Job.server_id == linux_id)).scalars().all()
                self.assertEqual(len(initial_jobs), len(INITIAL_SERVER_SCAN_ACTIONS))
                self.assertTrue(all(job.created_by == package.created_by for job in initial_jobs))
                self.assertTrue(all(len(job.created_by) <= 36 for job in initial_jobs))
            replay = client.post("/api/v1/agent-bootstrap/claim", json=linux_claim)
            self.assertEqual(replay.status_code, 401)
            with SessionLocal() as db:
                denial = db.execute(
                    select(AuditEvent)
                    .where(AuditEvent.action == "agent.package.claim.denied", AuditEvent.target == bootstrap["package_id"])
                    .order_by(AuditEvent.occurred_at.desc())
                    .limit(1)
                ).scalar_one()
                self.assertEqual(denial.result, "blocked")
                self.assertEqual(denial.detail["reason"], "already_used")
                self.assertNotIn("secret", denial.detail)

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
                nginx_linux = client.post("/api/v1/agent-packages", headers=headers, json={"label": "nginx-linux", "os_family": "linux", "linux_profile": "ubuntu-24.04", "expires_minutes": 15})
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

            with patch("app.main.scan_stream_with_clamav", return_value="stream: OK"):
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
            with SessionLocal() as db:
                transfer = db.get(FileTransfer, uploaded.json()["id"])
                chunks = db.execute(select(FileTransferChunk).where(FileTransferChunk.transfer_id == transfer.id).order_by(FileTransferChunk.sequence)).scalars().all()
                self.assertEqual(transfer.nonce, "chunks-v1")
                self.assertIsNone(transfer.content_encrypted)
                self.assertEqual(sum(chunk.plain_size for chunk in chunks), transfer.size_bytes)
                self.assertEqual(len(chunks), 1)
            self.assertEqual(b"".join(stream_file_transfer_chunks(uploaded.json()["id"])), b"setting: approved\n")

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
        rotated_typescript = recording_root / f"{session_id}.typescript.1"
        typescript_timing = recording_root / f"{session_id}.typescript.1.timing"
        recording.write_bytes(b"guacamole-recording")
        typescript.write_bytes(b"terminal-text")
        rotated_typescript.write_bytes(b"rotated-terminal-text")
        typescript_timing.write_bytes(b"0.1 10\n")
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
                self.assertFalse(rotated_typescript.exists())
                self.assertFalse(typescript_timing.exists())
            with SessionLocal() as db:
                self.assertEqual(db.get(RecordingDeletionRequest, deletion_id).status, "deleted")
        finally:
            settings.recording_root = original_root

    def test_recording_retention_deletes_only_old_closed_session_files(self):
        original_root = settings.recording_root
        recording_root = Path(tmp.name) / f"recording-retention-{uuid.uuid4()}"
        recording_root.mkdir()
        settings.recording_root = str(recording_root)
        server_id = str(uuid.uuid4())
        old_session_id = str(uuid.uuid4())
        active_session_id = str(uuid.uuid4())
        old_recording = recording_root / f"{old_session_id}-admin.guac"
        old_typescript = recording_root / f"{old_session_id}.typescript"
        recent_recording = recording_root / f"{uuid.uuid4()}-admin.guac"
        active_recording = recording_root / f"{active_session_id}-admin.guac"
        unrelated = recording_root / "not-a-recording.log"
        for path in (old_recording, old_typescript, recent_recording, active_recording, unrelated):
            path.write_bytes(b"recording")
        old_timestamp = (datetime.now(UTC) - timedelta(days=181)).timestamp()
        for path in (old_recording, old_typescript, active_recording, unrelated):
            os.utime(path, (old_timestamp, old_timestamp))
        try:
            with SessionLocal() as db:
                db.add_all([
                    Server(id=server_id, name="retention-test", os_family="windows", os_name="Windows Server"),
                    RemoteSession(id=old_session_id, server_id=server_id, protocol="rdp", remote_username="admin", created_by="admin", status="closed", recording_name=old_recording.name),
                    RemoteSession(id=active_session_id, server_id=server_id, protocol="rdp", remote_username="admin", created_by="admin", status="waiting", recording_name=active_recording.name),
                ])
                db.merge(SystemSetting(key="recording_retention", value=json.dumps({"enabled": True, "days": 180})))
                db.commit()
                result = prune_recording_files(db)
                db.commit()
                self.assertEqual(result["deletedFiles"], 2)
                self.assertEqual(result["errors"], 0)
            self.assertFalse(old_recording.exists())
            self.assertFalse(old_typescript.exists())
            self.assertTrue(recent_recording.exists())
            self.assertTrue(active_recording.exists())
            self.assertTrue(unrelated.exists())
            with TestClient(app) as client:
                headers = {"Authorization": f"Bearer {self.login_admin(client)}"}
                configured = client.put("/api/v1/settings/recording-retention", headers=headers, json={"enabled": True, "days": 210})
                self.assertEqual(configured.status_code, 200, configured.text)
                self.assertEqual(configured.json()["days"], 210)
                self.assertIn("lastRun", configured.json())
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
