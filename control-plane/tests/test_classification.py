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
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import pyotp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from fastapi.routing import APIRoute
from sqlalchemy import select

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
source_agent_assets = Path(__file__).resolve().parents[2] / "agent"
test_agent_assets = Path(tmp.name) / "agent-assets"
(test_agent_assets / "linux/x86_64").mkdir(parents=True)
for asset_name in ("VERSION", "install-linux.sh", "tram-agent.service"):
    shutil.copyfile(source_agent_assets / asset_name, test_agent_assets / asset_name)
fake_linux_agent = bytearray(1024 * 1024)
fake_linux_agent[:6] = b"\x7fELF\x02\x01"
fake_linux_agent[18:20] = b"\x3e\x00"
(test_agent_assets / "linux/x86_64/tram-agent").write_bytes(fake_linux_agent)
os.environ["AGENT_ASSETS_ROOT"] = str(test_agent_assets)

from app.main import AUTO_REFRESH_ACTIONS, INITIAL_SERVER_SCAN_ACTIONS, AgentBootstrapPackage, AuditEvent, AuthThrottle, BulkTask, BulkTaskItem, FileTransfer, Inventory, Job, RecordingDeletionRequest, RemoteSession, Server, SessionLocal, SystemSetting, User, classify_os, current_user, guacamole_launch_url, guacamole_rdp_certificate_fingerprint, guacamole_ssh_host_key, issue_jwt, prune_audit_events, prune_recording_files, recording_file, recording_probe, retire_legacy_pending_jobs, settings, validate_firewall_job_parameters, validate_job_parameters, validate_log_sources  # noqa: E402
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
        finally:
            with SessionLocal() as db:
                stored = db.get(User, viewer_id)
                if stored:
                    db.delete(stored)
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
                self.assertGreater(len(archive.extractfile("linux/x86_64/tram-agent").read()), 1024 * 512)
                self.assertTrue(all(member.mtime >= 1_704_067_200 for member in archive.getmembers()))
                self.assertNotIn("requirements.txt", archive.getnames())
                self.assertNotIn("tram_agent.py", archive.getnames())
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
