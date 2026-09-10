"""API-level role/approval regressions. Reuse the existing disposable test DB."""
import base64
import json
import unittest
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import test_classification  # initializes the existing temporary fixture, never production data
from app import main as m
from fastapi.testclient import TestClient
from sqlalchemy import select


class RolePolicyTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(m.app)
        self.client.__enter__()
        self.headers = {}
        self.ids = {}
        with m.SessionLocal() as db:
            for role in ("admin", "operator", "viewer", "auditor", "connector"):
                actor = m.User(username=role + "-" + uuid.uuid4().hex[:10], password_hash="!test", display_name=role, role=role, enabled=True)
                db.add(actor)
                db.flush()
                self.ids[role] = actor.id
                self.headers[role] = {"Authorization": "Bearer " + m.issue_jwt(actor)}
            self.server_id = str(uuid.uuid4())
            db.add(m.Server(id=self.server_id, name="rbac-" + self.server_id[:8], os_family="linux", os_name="Ubuntu", os_version="24.04", distribution_id="ubuntu", address="10.80.3.7"))
            db.commit()

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def job(self, role, action="storage.delete", parameters=None):
        return self.client.post("/api/v1/jobs", headers=self.headers[role], json={"server_id": self.server_id, "action": action, "parameters": parameters if parameters is not None else {"kind": "linux_partition", "path": "/dev/sdb1"}, "reason": "CHG regression test"})

    def review(self, identifier, role="admin", decision="approve"):
        return self.client.post(f"/api/v1/deletion-approvals/{identifier}/review", headers=self.headers[role], json={"decision": decision})

    def test_managed_target_routes_exist_and_remain_protected(self):
        for path in ("/api/v1/managed-targets", "/api/v1/deletion-approvals", "/api/v1/configuration-snapshot"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 401, (path, response.text))

    def test_operator_and_viewer_see_unshared_servers_but_connector_does_not(self):
        for role in ("operator", "viewer"):
            response = self.client.get("/api/v1/servers", headers=self.headers[role])
            self.assertIn(self.server_id, {item["id"] for item in response.json()["items"]})
        hidden = self.client.get("/api/v1/servers", headers=self.headers["connector"])
        self.assertEqual(hidden.json()["items"], [])
        for suffix in ("", "/jobs", "/files", "/log-sources"):
            self.assertIn(self.client.get(f"/api/v1/servers/{self.server_id}{suffix}", headers=self.headers["connector"]).status_code, (403, 404))

    def test_readonly_roles_cannot_create_jobs_even_read_scans(self):
        for role in ("viewer", "auditor", "connector"):
            for action in ("inventory.collect", "logs.read", "service.restart", "storage.delete"):
                self.assertEqual(self.job(role, action, {}).status_code, 403)
            response = self.client.post("/api/v1/bulk-tasks", headers=self.headers[role], json={"os_family": "linux", "server_ids": [self.server_id], "action": "patch.source.read", "parameters": {}, "reason": "read-only test"})
            self.assertEqual(response.status_code, 403)

    def test_auditor_only_has_audit_and_logs(self):
        for endpoint in ("audit", "logs"):
            self.assertEqual(self.client.get("/api/v1/" + endpoint, headers=self.headers["auditor"]).status_code, 200)
        for endpoint in ("servers", "managed-targets", "jobs", "sessions", "configuration-snapshot", "users", "remote-credentials"):
            self.assertEqual(self.client.get("/api/v1/" + endpoint, headers=self.headers["auditor"]).status_code, 403)

    def test_operator_cannot_manage_identity_or_approve(self):
        for endpoint in ("users", "roles", "settings/ldap", "remote-credentials"):
            self.assertEqual(self.client.get("/api/v1/" + endpoint, headers=self.headers["operator"]).status_code, 403)
        self.assertEqual(self.job("operator", "user.delete", {"usernames": ["unused"]}).status_code, 403)
        self.assertEqual(self.review(str(uuid.uuid4()), "operator").status_code, 403)

    def test_deletion_is_not_dispatched_until_one_admin_approves_exactly_once(self):
        created = self.job("operator")
        self.assertEqual(created.status_code, 201, created.text)
        identifier = created.json()["approvalId"]
        self.assertEqual(created.json()["status"], "pending_approval")
        with m.SessionLocal() as db:
            self.assertIsNone(db.execute(select(m.Job).where(m.Job.server_id == self.server_id)).scalars().first())
        self.assertEqual(self.job("operator").status_code, 409)
        self.assertEqual(self.review(identifier, "operator").status_code, 403)
        approved = self.review(identifier)
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(self.review(identifier).status_code, 409)
        with m.SessionLocal() as db:
            jobs = db.execute(select(m.Job).where(m.Job.server_id == self.server_id)).scalars().all()
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0].parameters, {"kind": "linux_partition", "path": "/dev/sdb1"})
            self.assertEqual(jobs[0].status, "queued")
            self.assertEqual(db.get(m.DeletionApproval, identifier).reviewed_by, self.ids["admin"])

    def test_operator_server_delete_preserves_server_until_admin_review(self):
        response = self.client.request("DELETE", f"/api/v1/servers/{self.server_id}", headers=self.headers["operator"], json={"confirmation": "DELETE", "reason": "retire test server"})
        self.assertEqual(response.status_code, 200, response.text)
        with m.SessionLocal() as db:
            self.assertIsNone(db.get(m.ServerRetirement, self.server_id))
        approved = self.review(response.json()["approvalId"])
        self.assertEqual(approved.status_code, 200, approved.text)
        with m.SessionLocal() as db:
            self.assertIsNotNone(db.get(m.ServerRetirement, self.server_id))
            self.assertIsNotNone(db.get(m.Server, self.server_id))

    def test_rejected_expired_or_revoked_requests_do_not_create_jobs(self):
        rejected = self.job("operator").json()["approvalId"]
        self.assertEqual(self.review(rejected, decision="reject").status_code, 200)
        self.assertEqual(self.review(rejected).status_code, 409)
        expired = self.job("operator").json()["approvalId"]
        with m.SessionLocal() as db:
            db.get(m.DeletionApproval, expired).created_at = m.now() - timedelta(hours=25)
            db.commit()
        self.assertEqual(self.review(expired).status_code, 409)
        revoked = self.job("operator").json()["approvalId"]
        with m.SessionLocal() as db:
            db.get(m.User, self.ids["operator"]).enabled = False
            db.commit()
        self.assertEqual(self.review(revoked).status_code, 409)
        with m.SessionLocal() as db:
            self.assertEqual(db.execute(select(m.Job).where(m.Job.server_id == self.server_id)).scalars().all(), [])

    def test_manual_connections_persist_share_and_use_same_delete_approval(self):
        for kind, port, url in (("network", 22, ""), ("web", 443, "https://vcenter.example.test/ui/")):
            payload = {"name": kind + "-" + uuid.uuid4().hex[:8], "kind": kind, "address": "10.80.3.9", "port": port, "url": url}
            for role in ("viewer", "connector", "auditor"):
                self.assertEqual(self.client.post("/api/v1/managed-targets", headers=self.headers[role], json=payload).status_code, 403)
            saved = self.client.post("/api/v1/managed-targets", headers=self.headers["operator"], json=payload)
            self.assertEqual(saved.status_code, 201, saved.text)
            identifier = saved.json()["id"]
            self.assertNotIn(identifier, {item["id"] for item in self.client.get("/api/v1/servers", headers=self.headers["operator"]).json()["items"]})
            self.assertNotIn(identifier, {item["id"] for item in self.client.get("/api/v1/managed-targets", headers=self.headers["connector"]).json()["items"]})
            shared = self.client.put(f"/api/v1/servers/{identifier}/shares", headers=self.headers["admin"], json={"user_ids": [self.ids["connector"]], "group_ids": []})
            self.assertEqual(shared.status_code, 200, shared.text)
            self.assertIn(identifier, {item["id"] for item in self.client.get("/api/v1/managed-targets", headers=self.headers["connector"]).json()["items"]})
            rejected_url = dict(payload, kind="web", port=443, url="https://user:secret@vcenter.example.test/")
            self.assertEqual(self.client.put(f"/api/v1/managed-targets/{identifier}", headers=self.headers["operator"], json=rejected_url).status_code, 422)

    def test_viewer_snapshot_never_contains_credential_passwords_or_ldap_bind_secrets(self):
        response = self.client.get("/api/v1/configuration-snapshot", headers=self.headers["viewer"])
        self.assertEqual(response.status_code, 200, response.text)
        for forbidden in ("password_hash", "password_encrypted", "bind_password", "private_key"):
            self.assertNotIn(forbidden, response.text)

    def test_operator_can_create_target_with_initial_credential_but_cannot_manage_vault(self):
        secret = "  initial-only-test-password  "
        for kind in ("network", "web"):
            payload = {"name": "initial-" + uuid.uuid4().hex[:8], "kind": kind, "credential": {"username": "ops-initial", "password": secret}}
            payload.update({"address": "10.80.9.7", "port": 22} if kind == "network" else {"url": "https://vcenter.example.test:8443/ui/"})
            response = self.client.post("/api/v1/managed-targets", headers=self.headers["operator"], json=payload)
            self.assertEqual(response.status_code, 201, response.text)
            server_id = response.json()["id"]
            with m.SessionLocal() as db:
                server = db.get(m.Server, server_id)
                stored = db.execute(select(m.RemoteCredential).where(m.RemoteCredential.server_id == server_id)).scalar_one()
                credential_id = stored.id
                self.assertEqual(m.decrypt_remote_credential_password(stored), secret)
                self.assertNotIn("credential", server.inventory["managedTarget"])
                self.assertNotIn(secret, json.dumps(server.inventory))
                self.assertNotEqual(stored.password_encrypted, secret)
                self.assertEqual(stored.protocol, "web" if kind == "web" else "ssh")
                if kind == "web":
                    self.assertEqual((server.address, server.inventory["managedTarget"]["port"]), ("vcenter.example.test", 8443))
            choices = self.client.get(f"/api/v1/servers/{server_id}/remote-credentials?protocol={'web' if kind == 'web' else 'ssh'}", headers=self.headers["operator"])
            self.assertEqual(choices.status_code, 200, choices.text)
            self.assertEqual(choices.json()["items"][0]["username"], "ops-initial")
            for text in (response.text, choices.text, self.client.get("/api/v1/managed-targets", headers=self.headers["operator"]).text, self.client.get("/api/v1/audit", headers=self.headers["admin"]).text):
                self.assertNotIn(secret, text)
                self.assertNotIn("password_encrypted", text)
            for method, endpoint, body in (
                ("GET", "/api/v1/remote-credentials", None),
                ("POST", "/api/v1/remote-credentials", {"server_id": server_id, "protocol": "web" if kind == "web" else "ssh", "label": "other", "username": "other", "password": "other"}),
                ("PUT", f"/api/v1/remote-credentials/{credential_id}", {"label": "changed", "username": "changed", "password": "changed"}),
                ("DELETE", f"/api/v1/remote-credentials/{credential_id}", None),
            ):
                self.assertEqual(self.client.request(method, endpoint, headers=self.headers["operator"], json=body).status_code, 403)
            self.assertEqual(self.client.put(f"/api/v1/managed-targets/{server_id}", headers=self.headers["operator"], json=payload).status_code, 403)
            rename = {key: value for key, value in payload.items() if key != "credential"}
            rename["name"] += "-renamed"
            self.assertEqual(self.client.put(f"/api/v1/managed-targets/{server_id}", headers=self.headers["operator"], json=rename).status_code, 200)
            redirected = dict(rename, **({"address": "10.80.9.8"} if kind == "network" else {"url": "https://other.example.test/"}))
            self.assertEqual(self.client.put(f"/api/v1/managed-targets/{server_id}", headers=self.headers["operator"], json=redirected).status_code, 403)
            vault = self.client.get("/api/v1/remote-credentials", headers=self.headers["admin"])
            self.assertIn(credential_id, {item["id"] for item in vault.json()["items"]})

    def test_initial_credentials_are_transactional_and_never_echoed_on_validation_errors(self):
        payload = {"name": "duplicate-" + uuid.uuid4().hex[:8], "kind": "web", "url": "https://vcenter.example.test/ui/", "credential": {"username": "initial", "password": "private-fixture-only"}}
        first = self.client.post("/api/v1/managed-targets", headers=self.headers["admin"], json=payload)
        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(self.client.post("/api/v1/managed-targets", headers=self.headers["operator"], json=payload).status_code, 409)
        with m.SessionLocal() as db:
            self.assertEqual(len(db.execute(select(m.RemoteCredential).where(m.RemoteCredential.server_id == first.json()["id"])).scalars().all()), 1)
        payload["credential"]["username"] = ""
        error = self.client.post("/api/v1/managed-targets", headers=self.headers["operator"], json=payload)
        self.assertEqual(error.status_code, 422)
        self.assertNotIn("private-fixture-only", error.text)

    def network_fixture(self, kind="network"):
        payload = {"name": "session-" + uuid.uuid4().hex[:8], "kind": kind, "credential": {"username": "switch-user", "password": "session-secret-fixture"}}
        payload.update({"address": "10.80.9.7", "port": 2222} if kind == "network" else {"url": "https://console.example.test/"})
        response = self.client.post("/api/v1/managed-targets", headers=self.headers["operator"], json=payload)
        self.assertEqual(response.status_code, 201, response.text)
        server_id = response.json()["id"]
        with m.SessionLocal() as db:
            credential = db.execute(select(m.RemoteCredential).where(m.RemoteCredential.server_id == server_id)).scalar_one()
            credential_id = credential.id
        return server_id, credential_id

    def test_managed_ssh_uses_saved_credentials_pins_first_key_and_records(self):
        server_id, credential_id = self.network_fixture()
        data = {"server_id": server_id, "protocol": "ssh", "credential_id": credential_id}
        host_key = "ssh-ed25519 " + base64.b64encode(b"test-ed25519-host-key-material").decode()
        with patch.object(m, "discover_host_key", new_callable=AsyncMock, return_value=host_key) as scan, patch.object(m.direct_hub, "create_listener", new_callable=AsyncMock, return_value=49000) as relay, patch.object(m.tunnel_hub, "create_listener", new_callable=AsyncMock) as agent_relay, patch.object(m, "encrypt_guacamole_json", return_value="opaque-fixture") as encrypt:
            # Legacy metadata used empty string rather than NULL.
            with m.SessionLocal() as db:
                db.get(m.Server, server_id).ssh_host_key = ""
                db.commit()
            for _ in range(2):
                response = self.client.post("/api/v1/sessions/launch", headers=self.headers["operator"], json=data)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertTrue(response.json()["recording"])
                self.assertNotIn("session-secret-fixture", response.text)
            scan.assert_awaited_once_with("10.80.9.7", 2222)
            agent_relay.assert_not_awaited()
            self.assertEqual(relay.call_args.args[1:], (server_id, "10.80.9.7", 2222))
            parameters = next(iter(encrypt.call_args.args[0]["connections"].values()))["parameters"]
            self.assertEqual(parameters["password"], "session-secret-fixture")
            self.assertEqual(parameters["username"], "switch-user")
            self.assertIn(host_key, parameters["host-key"])
            self.assertEqual(parameters["recording-exclude-output"], "false")
            self.assertEqual(parameters["disable-paste"], "false")
            self.assertEqual(parameters["disable-copy"], "true")
            self.assertEqual(parameters["enable-sftp"], "false")
        with m.SessionLocal() as db:
            self.assertEqual(db.get(m.Server, server_id).ssh_host_key, host_key)
            events = db.execute(select(m.AuditEvent).where(m.AuditEvent.target == server_id)).scalars().all()
            self.assertNotIn("session-secret-fixture", str([event.detail for event in events]))

    def test_automatic_ssh_works_without_resaving_missing_false_or_true_legacy_metadata(self):
        for old_flag in (None, False, True):
            server_id, credential_id = self.network_fixture()
            with m.SessionLocal() as db:
                server = db.get(m.Server, server_id)
                config = dict(server.inventory["managedTarget"])
                self.assertNotIn("ssh_legacy_compatibility", config)
                # Reproduce rows saved by previous releases; do NOT PUT first.
                if old_flag is not None:
                    config["ssh_legacy_compatibility"] = old_flag
                    server.inventory = {"managedTarget": dict(config)}
                encrypted_password = db.get(m.RemoteCredential, credential_id).password_encrypted
                db.commit()
            host_key = "ssh-rsa " + base64.b64encode(b"fixture-rsa-host-key-material").decode()
            with patch("app.direct_sessions._run_probe", new_callable=AsyncMock, return_value=(b"", b"no matching key exchange method")) as modern, patch("app.direct_sessions._discover_legacy_host_key", new_callable=AsyncMock, return_value=host_key) as legacy, patch.object(m.direct_hub, "create_listener", new_callable=AsyncMock, return_value=49000), patch.object(m, "encrypt_guacamole_json", return_value="opaque-fixture"):
                for _ in range(2):
                    response = self.client.post("/api/v1/sessions/launch", headers=self.headers["operator"], json={"server_id": server_id, "protocol": "ssh", "credential_id": credential_id})
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertTrue(response.json()["recording"])
                modern.assert_awaited_once()
                legacy.assert_awaited_once_with("10.80.9.7", 2222)
            endpoint = f"/api/v1/managed-targets/{server_id}"
            config["ssh_legacy_compatibility"] = False  # stale form still accepted
            for role in ("viewer", "connector", "auditor"):
                self.assertEqual(self.client.put(endpoint, headers=self.headers[role], json=config).status_code, 403)
            self.assertEqual(self.client.put(endpoint, headers=self.headers["operator"], json=config).status_code, 200)
            with m.SessionLocal() as db:
                self.assertEqual(db.get(m.Server, server_id).ssh_host_key, host_key)
                self.assertNotIn("ssh_legacy_compatibility", db.get(m.Server, server_id).inventory["managedTarget"])
                self.assertEqual(db.get(m.RemoteCredential, credential_id).password_encrypted, encrypted_password)
                events = db.execute(select(m.AuditEvent).where(m.AuditEvent.target == server_id, m.AuditEvent.action == "target.ssh.trust_first_use")).scalars().all()
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0].detail["ssh_compatibility"], "automatic-modern-first-group14-rsa-sha1")
            config["ssh_legacy_compatibility"] = "true"
            self.assertEqual(self.client.put(endpoint, headers=self.headers["operator"], json=config).status_code, 422)

    def test_ssh_probe_failure_is_actionable_audited_and_does_not_open_relay(self):
        server_id, credential_id = self.network_fixture()
        for code, status in [("algorithms_unsupported", 409), ("probe_unavailable", 503)]:
            with patch.object(m, "discover_host_key", new_callable=AsyncMock, side_effect=m.SSHProbeError(code, "Thông báo SSH an toàn")), patch.object(m.direct_hub, "create_listener", new_callable=AsyncMock) as relay:
                response = self.client.post("/api/v1/sessions/launch", headers=self.headers["operator"], json={"server_id": server_id, "protocol": "ssh", "credential_id": credential_id})
                self.assertEqual(response.status_code, status, response.text)
                self.assertEqual(response.json()["detail"], "Thông báo SSH an toàn")
                relay.assert_not_awaited()
        with m.SessionLocal() as db:
            self.assertFalse(db.get(m.Server, server_id).ssh_host_key)
            events = db.execute(select(m.AuditEvent).where(m.AuditEvent.target == server_id, m.AuditEvent.action == "target.ssh.preflight_failed")).scalars().all()
            self.assertEqual({event.detail["code"] for event in events}, {"algorithms_unsupported", "probe_unavailable"})

    def test_ssh_requires_both_target_and_credential_share_and_readonly_roles_cannot_launch(self):
        server_id, credential_id = self.network_fixture()
        data = {"server_id": server_id, "protocol": "ssh", "credential_id": credential_id}
        with patch.object(m.direct_hub, "create_listener", new_callable=AsyncMock) as relay, patch.object(m, "discover_host_key", new_callable=AsyncMock):
            for role in ("viewer", "auditor", "connector"):
                self.assertIn(self.client.post("/api/v1/sessions/launch", headers=self.headers[role], json=data).status_code, (403, 404))
            with m.SessionLocal() as db:
                db.add(m.ServerUserShare(server_id=server_id, user_id=self.ids["connector"], granted_by=self.ids["admin"]))
                db.commit()
            self.assertEqual(self.client.post("/api/v1/sessions/launch", headers=self.headers["connector"], json=data).status_code, 403)
            self.assertEqual(self.client.get(f"/api/v1/servers/{server_id}/remote-credentials?protocol=ssh", headers=self.headers["connector"]).json()["items"], [])
            relay.assert_not_awaited()
        with m.SessionLocal() as db:
            db.add(m.RemoteCredentialUserShare(credential_id=credential_id, user_id=self.ids["connector"], granted_by=self.ids["admin"]))
            db.get(m.Server, server_id).ssh_host_key = "ssh-ed25519 " + base64.b64encode(b"test-ed25519-host-key-material").decode()
            db.commit()
        with patch.object(m.direct_hub, "create_listener", new_callable=AsyncMock, return_value=49000), patch.object(m, "encrypt_guacamole_json", return_value="opaque-fixture"):
            self.assertEqual(self.client.post("/api/v1/sessions/launch", headers=self.headers["connector"], json=data).status_code, 200)
            wrong_server = dict(data, server_id=self.server_id)
            self.assertEqual(self.client.post("/api/v1/sessions/launch", headers=self.headers["admin"], json=wrong_server).status_code, 404)

    def test_web_launch_fails_closed_without_decrypting_or_sending_credentials(self):
        server_id, credential_id = self.network_fixture("web")
        with patch.object(m, "decrypt_remote_credential_password") as decrypt, patch.object(m.direct_hub, "create_listener", new_callable=AsyncMock) as relay:
            response = self.client.post("/api/v1/sessions/launch", headers=self.headers["operator"], json={"server_id": server_id, "protocol": "web", "credential_id": credential_id})
            self.assertEqual(response.status_code, 503)
            decrypt.assert_not_called()
            relay.assert_not_awaited()

    def test_web_launch_uses_internal_recorded_browser_without_vault_decryption(self):
        server_id, credential_id = self.network_fixture("web")
        with patch.object(m.web_hub, "base_url", "http://web-console:8081"), patch.object(m.web_hub, "secret", lambda: "a" * 32), patch.object(m.web_hub, "prepare", new_callable=AsyncMock, return_value={"port": 45000, "password": "vnc12345"}) as prepare, patch.object(m.web_hub, "watch") as watch, patch.object(m, "decrypt_remote_credential_password") as decrypt, patch.object(m, "encrypt_guacamole_json", return_value="opaque-fixture") as encrypt:
            response = self.client.post("/api/v1/sessions/launch", headers=self.headers["operator"], json={"server_id": server_id, "protocol": "web", "credential_id": credential_id})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(response.json()["recording"])
            self.assertTrue(response.json()["url"].startswith("/guacamole/"))
            self.assertNotIn("console.example.test", response.text)
            decrypt.assert_not_called()
            prepare.assert_awaited_once()
            self.assertEqual(prepare.call_args.args[1], "https://console.example.test/")
            connection = next(iter(encrypt.call_args.args[0]["connections"].values()))
            self.assertEqual(connection["protocol"], "vnc")
            self.assertEqual(connection["parameters"]["hostname"], "web-console")
            self.assertEqual(connection["parameters"]["password"], "vnc12345")
            self.assertEqual(connection["parameters"]["recording-include-keys"], "false")
            self.assertEqual(connection["parameters"]["disable-copy"], "true")
            self.assertEqual(connection["parameters"]["disable-paste"], "false")
            identifier, _probe, authorize, activate, finish = watch.call_args.args
            self.assertTrue(authorize())
            with patch.object(m.web_hub, "call", new_callable=AsyncMock, return_value={"status": "active"}) as call:
                self.client.portal.call(activate)
                call.assert_awaited_once_with("POST", f"/sessions/{identifier}/activate", {})
            with m.SessionLocal() as db:
                self.assertEqual(db.get(m.RemoteSession, identifier).status, "active")
                db.get(m.User, self.ids["operator"]).enabled = False
                db.commit()
            self.assertFalse(authorize())
            self.client.portal.call(finish, identifier, "web-access-revoked")
            with m.SessionLocal() as db:
                self.assertEqual(db.get(m.RemoteSession, identifier).status, "failed")
                self.assertIsNotNone(db.get(m.RemoteSession, identifier).finished_at)

    def test_web_launch_requires_both_target_and_credential_share_and_cleans_failure(self):
        server_id, credential_id = self.network_fixture("web")
        data = {"server_id": server_id, "protocol": "web", "credential_id": credential_id}
        with patch.object(m.web_hub, "base_url", "http://web-console:8081"), patch.object(m.web_hub, "secret", lambda: "a" * 32), patch.object(m.web_hub, "prepare", new_callable=AsyncMock, side_effect=m.WebSessionError("unavailable")) as prepare, patch.object(m.web_hub, "stop_remote", new_callable=AsyncMock) as stop, patch.object(m, "decrypt_remote_credential_password") as decrypt:
            for role in ("viewer", "auditor", "connector"):
                self.assertIn(self.client.post("/api/v1/sessions/launch", headers=self.headers[role], json=data).status_code, (403, 404))
            prepare.assert_not_awaited()
            with m.SessionLocal() as db:
                db.add(m.ServerUserShare(server_id=server_id, user_id=self.ids["connector"], granted_by=self.ids["admin"]))
                db.commit()
            self.assertEqual(self.client.post("/api/v1/sessions/launch", headers=self.headers["connector"], json=data).status_code, 403)
            prepare.assert_not_awaited()
            self.assertEqual(self.client.post("/api/v1/sessions/launch", headers=self.headers["operator"], json=data).status_code, 503)
            stop.assert_awaited_once()
            decrypt.assert_not_called()
            with m.SessionLocal() as db:
                self.assertEqual(db.execute(select(m.RemoteSession).where(m.RemoteSession.server_id == server_id)).scalars().all(), [])

    def test_operator_recording_deletion_needs_one_admin_and_rejects_active_session(self):
        root = Path(test_classification.tmp.name) / ("role-recordings-" + uuid.uuid4().hex)
        root.mkdir()
        identifier = str(uuid.uuid4())
        path = root / (identifier + ".guac")
        path.write_bytes(b"recording fixture")
        with m.SessionLocal() as db:
            db.add(m.RemoteSession(id=identifier, server_id=self.server_id, protocol="ssh", remote_username="managed", created_by="test", status="active", recording_name=identifier))
            db.commit()
        with patch.object(m.settings, "recording_root", str(root)):
            payload = {"session_ids": [identifier], "reason": "CHG remove test recording"}
            endpoint = "/api/v1/recording-deletion-requests"
            self.assertEqual(self.client.post(endpoint, headers=self.headers["operator"], json=payload).status_code, 409)
            with m.SessionLocal() as db:
                db.get(m.RemoteSession, identifier).status = "closed"
                db.commit()
            pending = self.client.post(endpoint, headers=self.headers["operator"], json=payload)
            self.assertEqual(pending.status_code, 201, pending.text)
            review = endpoint + "/" + pending.json()["id"] + "/approve"
            self.assertTrue(path.exists())
            self.assertEqual(self.client.post(review, headers=self.headers["operator"]).status_code, 403)
            self.assertEqual(self.client.post(review, headers=self.headers["admin"]).status_code, 200)
            self.assertFalse(path.exists())
            self.assertEqual(self.client.post(review, headers=self.headers["admin"]).status_code, 409)

    def test_failed_server_delete_rolls_back_approval(self):
        response = self.client.request("DELETE", f"/api/v1/servers/{self.server_id}", headers=self.headers["operator"], json={"confirmation": "DELETE", "reason": "retire active test"})
        approval_id = response.json()["approvalId"]
        with m.SessionLocal() as db:
            db.add(m.RemoteSession(server_id=self.server_id, protocol="ssh", remote_username="test", created_by="test", status="active", recording_name="fixture"))
            db.commit()
        self.assertEqual(self.review(approval_id).status_code, 409)
        with m.SessionLocal() as db:
            self.assertEqual(db.get(m.DeletionApproval, approval_id).status, "pending")
            self.assertIsNone(db.get(m.ServerRetirement, self.server_id))


if __name__ == "__main__":
    unittest.main()


def tearDownModule():
    # Release pooled SQLite fixture handles before Windows removes the temp dir.
    # Production continues to require PostgreSQL.
    if m.engine is not None:
        m.engine.dispose()
