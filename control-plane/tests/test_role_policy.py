"""API-level role/approval regressions. Reuse the existing disposable test DB."""
import json
import unittest
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

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
