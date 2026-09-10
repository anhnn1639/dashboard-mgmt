"""Delete logins without deleting historical identities, audit or recordings."""
import os
import tempfile
import unittest
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import test_classification  # Existing disposable fixture; never the deployment DB.
from app import main as m
from app.schema_migrations import detach_recording_history_users
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import sessionmaker


class UserDeletionTests(unittest.TestCase):
    def prepare_database(self):
        m.Base.metadata.create_all(m.engine)

    def setUp(self):
        self.prepare_database()
        self.client = TestClient(m.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.enterContext(patch.object(m.settings, "recording_root", directory.name))
        self.ids, self.names, self.headers = {}, {}, {}
        with m.SessionLocal() as db:
            for label, role in (("admin", "admin"), ("requester", "operator"), ("approver", "admin"), ("keep", "viewer")):
                user = m.User(username=f"delete-{label}-{uuid.uuid4().hex[:8]}", password_hash="!test", role=role)
                db.add(user)
                db.flush()
                self.ids[label], self.names[label] = user.id, user.username
                self.headers[label] = {"Authorization": "Bearer " + m.issue_jwt(user)}
            server = m.Server(id=str(uuid.uuid4()), name="deletion-fixture", os_family="linux", os_name="Ubuntu")
            db.add(server)
            db.flush()
            group = m.PlatformGroup(name="delete-" + uuid.uuid4().hex[:8], created_by=self.ids["requester"])
            credential = m.RemoteCredential(server_id=server.id, protocol="ssh", label="fixture", username="fixture", password_encrypted="not-a-real-secret", created_by=self.ids["requester"])
            db.add_all([group, credential])
            db.flush()
            self.server_id, self.credential_id = server.id, credential.id
            self.session_id = str(uuid.uuid4())
            db.add(m.RemoteSession(id=self.session_id, server_id=server.id, protocol="ssh", remote_username="fixture", created_by=self.names["requester"], status="closed", recording_name=self.session_id))
            for label in ("requester", "keep"):
                user_id = self.ids[label]
                db.add_all([
                    m.MFACredential(user_id=user_id, secret_encrypted="fixture-only"),
                    m.RevokedSessionToken(jti=str(uuid.uuid4()), user_id=user_id, expires_at=m.now() + timedelta(hours=1)),
                    m.PlatformGroupMember(group_id=group.id, user_id=user_id),
                    m.ServerUserShare(server_id=server.id, user_id=user_id, granted_by=self.ids["admin"]),
                    m.RemoteCredentialUserShare(credential_id=credential.id, user_id=user_id, granted_by=self.ids["admin"]),
                ])
            self.requests = {}
            for status in ("pending", "deleted", "failed", "deleting"):
                item = m.RecordingDeletionRequest(session_ids=[self.session_id], reason="CHG deletion fixture", status=status, requested_by=self.ids["requester"], requested_by_username=self.names["requester"], approved_by=self.ids["approver"] if status != "pending" else None, approved_by_username=self.names["approver"] if status != "pending" else "")
                db.add(item)
                db.flush()
                self.requests[status] = item.id
            approval = m.DeletionApproval(server_id=server.id, action="server.delete", parameters={}, reason="CHG fixture", requested_by=self.ids["requester"], requested_by_username=self.names["requester"])
            db.add(approval)
            db.flush()
            self.approval_id = approval.id
            m.audit(db, self.names["requester"], "session.recording.delete.request", self.requests["deleted"])
            m.audit(db, self.names["approver"], "session.recording.delete.approve", self.requests["deleted"])
            db.commit()
            events = db.execute(select(m.AuditEvent).where(m.AuditEvent.target == self.requests["deleted"])).scalars().all()
            self.history = {event.id: {column.name: getattr(event, column.name) for column in m.AuditEvent.__table__.columns} for event in events}
        self.recording = Path(directory.name) / self.session_id
        self.recording.write_bytes(b"synthetic recording fixture")

    def remove(self, ids=None, label="admin"):
        return self.client.request("DELETE", "/api/v1/users", headers=self.headers[label], json={"user_ids": ids if ids is not None else [self.ids["requester"], self.ids["approver"]]})

    def tearDown(self):
        self.client.close()
        m.engine.dispose()  # Release fixture file handles on Windows too.

    def test_delete_requester_and_approver_preserves_history_and_recording(self):
        self.assertEqual(self.client.get("/api/v1/me", headers=self.headers["requester"]).status_code, 200)
        response = self.remove()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {"deleted": 2})
        self.assertEqual(self.client.get("/api/v1/me", headers=self.headers["requester"]).status_code, 401)
        self.assertEqual(self.recording.read_bytes(), b"synthetic recording fixture")
        with m.SessionLocal() as db:
            for label in ("requester", "approver"):
                self.assertIsNone(db.get(m.User, self.ids[label]))
            self.assertIsNotNone(db.get(m.User, self.ids["keep"]))
            self.assertIsNotNone(db.get(m.RemoteSession, self.session_id))
            self.assertEqual(db.get(m.RemoteCredential, self.credential_id).password_encrypted, "not-a-real-secret")
            for model in (m.MFACredential, m.RevokedSessionToken, m.PlatformGroupMember, m.ServerUserShare, m.RemoteCredentialUserShare):
                self.assertEqual(db.execute(select(model).where(model.user_id == self.ids["requester"])).scalars().all(), [])
                self.assertIsNotNone(db.execute(select(model).where(model.user_id == self.ids["keep"])).scalars().first())
            for status, identifier in self.requests.items():
                item = db.get(m.RecordingDeletionRequest, identifier)
                self.assertEqual(item.status, "cancelled" if status == "pending" else status)
                self.assertEqual((item.requested_by, item.requested_by_username), (self.ids["requester"], self.names["requester"]))
                if status != "pending":
                    self.assertEqual((item.approved_by, item.approved_by_username), (self.ids["approver"], self.names["approver"]))
            self.assertEqual(db.get(m.DeletionApproval, self.approval_id).status, "cancelled")
            for identifier, before in self.history.items():
                event = db.get(m.AuditEvent, identifier)
                self.assertEqual({column.name: getattr(event, column.name) for column in m.AuditEvent.__table__.columns}, before)
            event = db.execute(select(m.AuditEvent).where(m.AuditEvent.action == "identity.user.delete", m.AuditEvent.actor == self.names["admin"])).scalar_one()
            self.assertEqual(event.detail["cancelled_recording_requests"], [self.requests["pending"]])
            self.assertEqual(event.detail["cancelled_deletion_approvals"], [self.approval_id])
        # A cancelled request cannot subsequently delete a file or retire a host.
        denied = self.client.post(f"/api/v1/recording-deletion-requests/{self.requests['pending']}/approve", headers=self.headers["admin"])
        self.assertEqual(denied.status_code, 409, denied.text)
        denied = self.client.post(f"/api/v1/deletion-approvals/{self.approval_id}/review", headers=self.headers["admin"], json={"decision": "approve"})
        self.assertEqual(denied.status_code, 409, denied.text)
        self.assertTrue(self.recording.exists())
        listed = self.client.get("/api/v1/recording-deletion-requests", headers=self.headers["admin"]).json()["items"]
        historical = next(item for item in listed if item["id"] == self.requests["deleted"])
        self.assertEqual(historical["requestedByUsername"], self.names["requester"])
        self.assertEqual(historical["approvedByUsername"], self.names["approver"])
        with m.SessionLocal() as db:
            # Reusing a login name creates a different identity, not inherited access.
            replacement = m.User(username=self.names["requester"], password_hash="!test", role="viewer")
            db.add(replacement)
            db.commit()
            self.assertNotEqual(replacement.id, self.ids["requester"])
        self.assertEqual(self.client.get("/api/v1/me", headers=self.headers["requester"]).status_code, 401)

    def test_delete_is_admin_only_and_batch_validation_is_atomic(self):
        for label in ("requester", "keep"):
            self.assertEqual(self.remove([self.ids["approver"]], label).status_code, 403)
        guest = self.client.request("DELETE", "/api/v1/users", json={"user_ids": [self.ids["requester"]]})
        self.assertEqual(guest.status_code, 401)
        for ids, code in (([self.ids["admin"], self.ids["requester"]], 409), ([self.ids["requester"], str(uuid.uuid4())], 404), ([self.ids["requester"]] * 2, 422)):
            response = self.remove(ids)
            self.assertEqual(response.status_code, code, response.text)
        with m.SessionLocal() as db:
            self.assertIsNotNone(db.get(m.User, self.ids["requester"]))
            self.assertEqual(db.get(m.RecordingDeletionRequest, self.requests["pending"]).status, "pending")

    def test_audit_failure_rolls_back_account_deletion_and_cancellations(self):
        with patch.object(m, "audit", side_effect=RuntimeError("synthetic audit write failure")):
            self.assertEqual(self.remove().status_code, 500)
        with m.SessionLocal() as db:
            self.assertIsNotNone(db.get(m.User, self.ids["requester"]))
            self.assertIsNotNone(db.get(m.MFACredential, self.ids["requester"]))
            self.assertEqual(db.get(m.RecordingDeletionRequest, self.requests["pending"]).status, "pending")
            self.assertEqual(db.get(m.DeletionApproval, self.approval_id).status, "pending")
        self.assertTrue(self.recording.exists())


@unittest.skipUnless(os.environ.get("TRAM_TEST_POSTGRES_URL"), "Disposable PostgreSQL integration runs in CI")
class PostgresUserDeletionTests(UserDeletionTests):
    def prepare_database(self):
        # Explicit opt-in test DB only. Each test owns a random schema; public
        # tables are never used or removed, including on a failed assertion.
        url = os.environ["TRAM_TEST_POSTGRES_URL"]
        schema = "test_user_deletion_" + uuid.uuid4().hex
        self.assertRegex(schema, r"^test_user_deletion_[0-9a-f]{32}$")
        admin_engine = create_engine(url)
        self.addCleanup(admin_engine.dispose)
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        def cleanup_schema():
            with admin_engine.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        self.addCleanup(cleanup_schema)
        engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
        self.addCleanup(engine.dispose)
        self.enterContext(patch.object(m, "engine", engine))
        self.enterContext(patch.object(m, "SessionLocal", sessionmaker(bind=engine, expire_on_commit=False)))
        m.Base.metadata.create_all(engine)
        # Reproduce an installed pre-fix schema, including custom FK names.
        with engine.begin() as connection:
            for column in ("requested_by", "approved_by"):
                connection.execute(text(f'ALTER TABLE recording_deletion_requests ADD CONSTRAINT "legacy {column}" FOREIGN KEY ({column}) REFERENCES users(id)'))

    def setUp(self):
        super().setUp()
        # Prove PostgreSQL really blocks deletion before the schema upgrade.
        from sqlalchemy.exc import IntegrityError
        with self.assertRaises(IntegrityError):
            with m.engine.begin() as connection:
                connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": self.ids["approver"]})
        self.assertEqual(detach_recording_history_users(m.engine), 2)
        self.assertEqual(detach_recording_history_users(m.engine), 0)
        self.assertEqual(inspect(m.engine).get_foreign_keys("recording_deletion_requests"), [])
        self.assertTrue(inspect(m.engine).get_foreign_keys("mfa_credentials"))


if __name__ == "__main__":
    unittest.main()
