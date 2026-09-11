"""Approval and deletion UI data contracts using only disposable fixture data."""
import os
import tempfile
import unittest
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import test_classification  # Existing isolated test database.
from app import main as m
from fastapi.testclient import TestClient
from sqlalchemy import select


class RecordingDeletionTests(unittest.TestCase):
    def setUp(self):
        m.Base.metadata.create_all(m.engine)
        self.client = TestClient(m.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.enterContext(patch.object(m.settings, "recording_root", directory.name))
        self.ids, self.headers = {}, {}
        with m.SessionLocal() as db:
            scoped_role = "rec-" + uuid.uuid4().hex[:8]
            db.add(m.PlatformRole(name=scoped_role, display_name="Scoped fixture", permissions=["recordings.view", "recordings.delete", "deletions.request"], system=False))
            db.flush()
            for label, role in (("requester", "admin"), ("approver", "admin"), ("operator", "operator"), ("scoped", scoped_role)):
                user = m.User(username=f"recording-{label}-{uuid.uuid4()}", password_hash="!", role=role)
                db.add(user)
                db.flush()
                self.ids[label] = user.id
                self.headers[label] = {"Authorization": "Bearer " + m.issue_jwt(user)}
            self.server_id = str(uuid.uuid4())
            db.add(m.Server(id=self.server_id, name="recording fixture", os_family="linux", os_name="Ubuntu"))
            db.flush()
            for label in ("operator", "scoped"):
                db.add(m.ServerUserShare(server_id=self.server_id, user_id=self.ids[label], granted_by=self.ids["requester"]))
            db.commit()

    def tearDown(self):
        self.client.close()
        m.engine.dispose()

    def session(self, suffixes=(".guac", ".typescript", ".typescript.1.timing", ".empty"), status="closed"):
        session_id = str(uuid.uuid4())
        with m.SessionLocal() as db:
            db.add(m.RemoteSession(id=session_id, server_id=self.server_id, protocol="ssh",
                remote_username="fixture", created_by="fixture", status=status, recording_name=session_id))
            db.commit()
        for suffix in suffixes:
            (self.root / (session_id + suffix)).write_bytes(b"" if suffix == ".empty" else b"recording")
        return session_id

    def request(self, ids, label="requester"):
        return self.client.post("/api/v1/recording-deletion-requests", headers=self.headers[label],
                                json={"session_ids": ids, "reason": "CHG fixture cleanup"})

    def review(self, identifier, decision="approve", label="approver"):
        return self.client.post(f"/api/v1/recording-deletion-requests/{identifier}/{decision}", headers=self.headers[label])

    def listed(self):
        response = self.client.get("/api/v1/sessions", headers=self.headers["approver"])
        self.assertEqual(response.status_code, 200, response.text)
        return {item["id"]: item for item in response.json()["items"]}

    def marker(self, session_id):
        with m.SessionLocal() as db:
            return db.get(m.RemoteSession, session_id).recording_deleted_at

    def test_success_hides_row_and_playback_preserves_history(self):
        session_id = self.session()
        request = self.request([session_id])
        self.assertEqual(request.status_code, 201, request.text)
        identifier = request.json()["id"]
        self.assertEqual(self.review(identifier, label="requester").status_code, 409)
        response = self.review(identifier)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "deleted")
        self.assertFalse(list(self.root.iterdir()))
        self.assertIsNotNone(self.marker(session_id))
        self.assertNotIn(session_id, self.listed())
        self.assertEqual(self.client.get(f"/api/v1/sessions/{session_id}/recording", headers=self.headers["approver"]).status_code, 404)
        with m.SessionLocal() as db:
            events = db.execute(select(m.AuditEvent).where(m.AuditEvent.target == identifier)).scalars().all()
            self.assertEqual([event.action for event in events], [
                "session.recording.delete.request", "session.recording.delete.approving", "session.recording.delete.approve"])
            self.assertEqual(events[-1].detail["files_deleted"], 4)
        self.assertEqual(self.review(identifier).status_code, 409)

    def test_reject_enforces_distinct_admin_and_keeps_files(self):
        session_id = self.session()
        identifier = self.request([session_id]).json()["id"]
        self.assertEqual(self.review(identifier, "reject", "requester").status_code, 409)
        for decision in ("approve", "reject"):
            for label in ("operator", "scoped"):
                self.assertEqual(self.review(identifier, decision, label).status_code, 403)
        response = self.review(identifier, "reject")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "rejected")
        self.assertEqual(len(list(self.root.iterdir())), 4)
        self.assertIsNone(self.marker(session_id))
        self.assertEqual(self.review(identifier).status_code, 409)
        self.assertEqual(self.request([session_id]).status_code, 201)

    def test_claim_audit_failure_does_not_remove_any_file(self):
        session_id = self.session()
        identifier = self.request([session_id]).json()["id"]
        with patch.object(m, "audit", side_effect=RuntimeError("fixture audit unavailable")):
            self.assertEqual(self.review(identifier).status_code, 500)
        self.assertEqual(len(list(self.root.iterdir())), 4)
        with m.SessionLocal() as db:
            self.assertEqual(db.get(m.RecordingDeletionRequest, identifier).status, "pending")
        self.assertIsNone(self.marker(session_id))

    def test_completion_audit_failure_recovers_without_deleting_again(self):
        session_id = self.session()
        identifier = self.request([session_id]).json()["id"]
        original_audit = m.audit
        def audit(db, actor, action, *args, **kwargs):
            if action == "session.recording.delete.approve":
                raise RuntimeError("fixture completion audit unavailable")
            return original_audit(db, actor, action, *args, **kwargs)
        with patch.object(m, "audit", side_effect=audit):
            self.assertEqual(self.review(identifier).status_code, 500)
        self.assertFalse(list(self.root.iterdir()))
        self.assertIsNone(self.marker(session_id))
        with m.SessionLocal() as db:
            item = db.get(m.RecordingDeletionRequest, identifier)
            self.assertEqual(item.status, "deleting")
            item.approved_at = m.now() - timedelta(minutes=3)
            db.commit()
        with patch.object(Path, "unlink", side_effect=AssertionError("recovery must never unlink")):
            self.assertNotIn(session_id, self.listed())
        self.assertIsNotNone(self.marker(session_id))
        with m.SessionLocal() as db:
            self.assertEqual(db.get(m.RecordingDeletionRequest, identifier).status, "deleted")
            event = db.execute(select(m.AuditEvent).where(m.AuditEvent.target == identifier,
                m.AuditEvent.action == "session.recording.delete.recovered")).scalar_one()
            self.assertEqual(event.result, "success")

    def test_interrupted_partial_deletion_releases_remaining_files_for_new_approval(self):
        complete, remaining = self.session(()), self.session((".typescript",))
        with m.SessionLocal() as db:
            item = m.RecordingDeletionRequest(session_ids=[complete, remaining], reason="fixture interrupted",
                status="deleting", approved_at=m.now() - timedelta(minutes=3),
                requested_by=self.ids["requester"], requested_by_username="fixture")
            db.add(item)
            db.commit()
            identifier = item.id
        self.assertNotIn(complete, self.listed())
        self.assertIsNone(self.marker(remaining))
        with m.SessionLocal() as db:
            self.assertEqual(db.get(m.RecordingDeletionRequest, identifier).status, "failed")
        self.assertEqual(self.request([remaining]).status_code, 201)

    def test_partial_batch_keeps_retryable_remnants_and_accurate_audit(self):
        first, second = self.session((".guac",)), self.session((".guac", ".typescript"))
        identifier = self.request([first, second]).json()["id"]
        failing = self.root / (second + ".typescript")
        real_unlink = Path.unlink
        def unlink(path, *args, **kwargs):
            if path == failing:
                raise PermissionError("fixture unlink denied")
            return real_unlink(path, *args, **kwargs)
        with patch.object(Path, "unlink", unlink):
            self.assertEqual(self.review(identifier).status_code, 500)
        self.assertIsNotNone(self.marker(first))
        self.assertIsNone(self.marker(second))
        rows = self.listed()
        self.assertNotIn(first, rows)
        self.assertFalse(rows[second]["recordingAvailable"])
        self.assertTrue(rows[second]["recordingDeletable"])
        with m.SessionLocal() as db:
            event = db.execute(select(m.AuditEvent).where(m.AuditEvent.target == identifier, m.AuditEvent.result == "failed")).scalar_one()
            self.assertEqual(event.detail["files_deleted"], 2)
        retry = self.request([second])
        self.assertEqual(retry.status_code, 201, retry.text)
        self.assertEqual(self.review(retry.json()["id"]).status_code, 200)
        self.assertNotIn(second, self.listed())

    def test_batch_preflight_rejects_nonfiles_before_removing_first_session(self):
        first, second = self.session((".guac",)), self.session((".guac",))
        identifier = self.request([first, second]).json()["id"]
        (self.root / (second + ".typescript")).mkdir()
        self.assertEqual(self.review(identifier).status_code, 500)
        self.assertTrue((self.root / (first + ".guac")).exists())
        self.assertIsNone(self.marker(first))
        self.assertIsNone(self.marker(second))

    def test_symlink_never_deletes_its_target(self):
        session_id = self.session((".guac",))
        identifier = self.request([session_id]).json()["id"]
        target = self.root / "unrelated-file"
        target.write_bytes(b"must remain")
        link = self.root / (session_id + ".typescript")
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("Symlink creation unavailable on this Windows host; runs on Linux CI")
        self.assertEqual(self.review(identifier).status_code, 500)
        self.assertEqual(target.read_bytes(), b"must remain")
        self.assertTrue(link.is_symlink())
        self.assertIsNone(self.marker(session_id))

    def test_missing_mount_fails_without_hiding_recording(self):
        session_id = self.session()
        identifier = self.request([session_id]).json()["id"]
        with patch.object(m.settings, "recording_root", str(self.root / "missing")):
            self.assertEqual(self.review(identifier).status_code, 500)
            self.assertIsNone(self.marker(session_id))
            self.assertIn(session_id, self.listed())
        self.assertEqual(len(list(self.root.iterdir())), 4)

    def test_legacy_success_reconciles_only_empty_healthy_storage(self):
        empty, remnant, pending = self.session(()), self.session((".empty",)), self.session(())
        with m.SessionLocal() as db:
            for session_id, status in ((empty, "deleted"), (remnant, "deleted"), (pending, "pending")):
                db.add(m.RecordingDeletionRequest(session_ids=[session_id], reason="old fixture",
                    status=status, requested_by=self.ids["requester"], requested_by_username="fixture"))
            db.commit()
        with patch.object(m.settings, "recording_root", str(self.root / "missing")):
            self.assertIn(empty, self.listed())
            self.assertIsNone(self.marker(empty))
        for _ in range(2):
            rows = self.listed()
            self.assertNotIn(empty, rows)
            self.assertIn(remnant, rows)
            self.assertIn(pending, rows)
        self.assertIsNone(self.marker(remnant))

    def test_changed_requester_permissions_or_share_prevent_deletion(self):
        for change in ("disabled", "role", "share"):
            with self.subTest(change=change):
                session_id = self.session()
                label = "scoped" if change == "share" else "requester"
                identifier = self.request([session_id], label).json()["id"]
                with m.SessionLocal() as db:
                    user = db.get(m.User, self.ids[label])
                    if change == "disabled":
                        user.enabled = False
                    elif change == "role":
                        user.role = "viewer"
                    else:
                        db.delete(db.get(m.ServerUserShare, (self.server_id, user.id)))
                    db.commit()
                self.assertEqual(self.review(identifier).status_code, 409)
                self.assertIsNone(self.marker(session_id))
                self.assertTrue((self.root / (session_id + ".guac")).exists())
                with m.SessionLocal() as db:
                    user = db.get(m.User, self.ids["requester"])
                    user.enabled, user.role = True, "admin"
                    db.commit()

    def test_deleted_rows_are_filtered_before_list_limit(self):
        visible = self.session((".guac",))
        with m.SessionLocal() as db:
            for _ in range(201):
                identifier = str(uuid.uuid4())
                db.add(m.RemoteSession(id=identifier, server_id=self.server_id, protocol="ssh", remote_username="fixture",
                    created_by="fixture", status="closed", recording_name=identifier, recording_deleted_at=m.now()))
            db.commit()
        self.assertIn(visible, self.listed())

    def test_polling_during_unlink_does_not_fail_entire_list(self):
        session_id = self.session((".guac",))
        original_probe = m.recording_probe
        def probe(identifier, *args, **kwargs):
            result = original_probe(identifier, *args, **kwargs)
            if identifier == session_id:
                (self.root / (session_id + ".guac")).unlink(missing_ok=True)
            return result
        with patch.object(m, "recording_probe", side_effect=probe):
            item = self.listed()[session_id]
        self.assertFalse(item["recordingAvailable"])
        self.assertEqual(item["recordingSizeBytes"], 0)

    def test_retention_marks_only_fully_removed_closed_recordings(self):
        complete, remnant, active = self.session((".guac",)), self.session((".guac", ".typescript")), self.session((".guac",), status="waiting")
        old = (m.now() - timedelta(days=181)).timestamp()
        for identifier in (complete, remnant, active):
            os.utime(self.root / (identifier + ".guac"), (old, old))
        with m.SessionLocal() as db:
            with patch.object(m, "read_recording_retention", return_value={"enabled": True, "days": 180}):
                result = m.prune_recording_files(db)
            db.commit()
        self.assertEqual(result["deletedFiles"], 2)
        self.assertIsNotNone(self.marker(complete))
        self.assertIsNone(self.marker(remnant))
        self.assertIsNone(self.marker(active))

    def test_active_approval_is_not_buried_by_newer_history(self):
        session_id = self.session()
        recording_id = self.request([session_id]).json()["id"]
        with m.SessionLocal() as db:
            operation = m.DeletionApproval(server_id=self.server_id, action="server.delete", parameters={}, reason="fixture",
                requested_by=self.ids["operator"], requested_by_username="fixture", created_at=m.now() - timedelta(hours=1))
            db.add(operation)
            db.flush()
            operation_id = operation.id
            for _ in range(205):
                db.add(m.DeletionApproval(server_id=self.server_id, action="server.delete", parameters={}, reason="fixture",
                    requested_by=self.ids["operator"], requested_by_username="fixture", status="rejected"))
                db.add(m.RecordingDeletionRequest(session_ids=[session_id], reason="fixture",
                    status="rejected", requested_by=self.ids["requester"], requested_by_username="fixture"))
            db.commit()
        for path, identifier in (("deletion-approvals", operation_id), ("recording-deletion-requests", recording_id)):
            response = self.client.get("/api/v1/" + path, headers=self.headers["approver"])
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn(identifier, [item["id"] for item in response.json()["items"]])


if __name__ == "__main__":
    unittest.main()
