"""Real PostgreSQL lock/cancellation regressions, isolated in a fresh schema."""
import asyncio
import os
import time
import unittest
import uuid
from unittest.mock import patch

import test_classification  # Existing disposable fixture initialization.
from app import main as m
from app.web_database import run_postgres
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, DataError


@unittest.skipUnless(os.environ.get("TRAM_TEST_POSTGRES_URL"), "Disposable PostgreSQL integration runs in CI")
class WebDatabasePostgresTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        base = make_url(os.environ["TRAM_TEST_POSTGRES_URL"])
        self.schema = "test_web_database_" + uuid.uuid4().hex
        admin = create_engine(base)
        with admin.begin() as db:
            db.execute(text(f'CREATE SCHEMA "{self.schema}"'))
        def cleanup():
            self.engine.dispose()
            with admin.begin() as db:
                db.execute(text(f'DROP SCHEMA "{self.schema}" CASCADE'))
            admin.dispose()
        self.addCleanup(cleanup)
        self.url = base.update_query_dict({"options": f"-csearch_path={self.schema}"})
        self.engine = create_engine(self.url)
        m.AuditEvent.__table__.create(self.engine)

    def append(self, db, actor="fixture"):
        m.audit(db, actor, "session.web.redirect_blocked", "target", result="denied",
                detail={"session_id": "session", "origin": "https://sso.test:443"})
        db.commit()

    async def test_locked_audit_rolls_back_without_stalling_loop_and_can_retry(self):
        blocker = self.engine.connect()
        transaction = blocker.begin()
        blocker.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": m.AUDIT_CHAIN_LOCK})
        ticks = []
        async def heartbeat():
            while True:
                ticks.append(time.monotonic())
                await asyncio.sleep(.02)
        heartbeat_task = asyncio.create_task(heartbeat())
        started = time.monotonic()
        try:
            with self.assertRaises((DBAPIError, TimeoutError)):
                await run_postgres(self.url, self.append)
        finally:
            transaction.rollback()
            blocker.close()
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)
        self.assertLess(time.monotonic() - started, 7)
        self.assertGreater(len(ticks), 10)
        with self.engine.connect() as db:
            self.assertEqual(len(db.execute(select(m.AuditEvent)).all()), 0)
        await run_postgres(self.url, self.append)
        with self.engine.connect() as db:
            self.assertEqual(len(db.execute(select(m.AuditEvent)).all()), 1)

    async def test_concurrent_audit_writers_and_clock_collision_keep_one_chain(self):
        fixed = m.now()
        def first(db):
            m.audit(db, "first", "fixture", "target")
            db.execute(text("SELECT pg_sleep(0.15)"))
            db.commit()
        with patch.object(m, "now", return_value=fixed):
            await asyncio.gather(run_postgres(self.url, first), run_postgres(self.url, lambda db: self.append(db, "second")))
        with self.engine.connect() as db:
            rows = db.execute(select(m.AuditEvent.previous_hash, m.AuditEvent.event_hash, m.AuditEvent.occurred_at).order_by(m.AuditEvent.occurred_at)).all()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].previous_hash, "0" * 64)
        self.assertEqual(rows[1].previous_hash, rows[0].event_hash)
        self.assertGreater(rows[1].occurred_at, rows[0].occurred_at)

    async def test_cancelled_query_releases_connection_and_transaction(self):
        started = asyncio.Event()
        def slow(db):
            m.lock_audit_chain(db)
            started.set()
            db.execute(text("SELECT pg_sleep(30)"))
        task = asyncio.create_task(run_postgres(self.url, slow))
        await asyncio.wait_for(started.wait(), 4)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, 6)
        await run_postgres(self.url, self.append)


    async def test_recording_recovery_skips_live_worker_row_lock(self):
        import tempfile
        from datetime import timedelta
        from sqlalchemy.orm import Session
        m.Base.metadata.create_all(self.engine)
        identifier, session_id, server_id = (str(uuid.uuid4()) for _ in range(3))
        with Session(self.engine) as db:
            db.add(m.Server(id=server_id, name="fixture", os_family="linux", os_name="fixture"))
            db.flush()
            db.add(m.RemoteSession(id=session_id, server_id=server_id, protocol="ssh",
                remote_username="fixture", created_by="fixture", status="closed", recording_name=session_id))
            db.add(m.RecordingDeletionRequest(id=identifier, session_ids=[session_id], reason="fixture",
                status="deleting", requested_by=str(uuid.uuid4()), requested_by_username="fixture",
                approved_at=m.now() - timedelta(minutes=3)))
            db.commit()
        with tempfile.TemporaryDirectory() as directory, patch.object(m.settings, "recording_root", directory):
            with Session(self.engine) as worker:
                worker.execute(select(m.RecordingDeletionRequest).where(
                    m.RecordingDeletionRequest.id == identifier).with_for_update()).scalar_one()
                started = time.monotonic()
                with Session(self.engine) as recovery:
                    m.reconcile_interrupted_recording_deletions(recovery)
                    self.assertEqual(recovery.get(m.RecordingDeletionRequest, identifier).status, "deleting")
                self.assertLess(time.monotonic() - started, 2)
                worker.rollback()
            with Session(self.engine) as recovery:
                m.reconcile_interrupted_recording_deletions(recovery)
                self.assertEqual(recovery.get(m.RecordingDeletionRequest, identifier).status, "deleted")
                self.assertIsNotNone(recovery.get(m.RemoteSession, session_id).recording_deleted_at)

    async def test_recording_deletion_marker_upgrade_preserves_old_sessions(self):
        from app.schema_migrations import add_recording_deletion_timestamp
        from sqlalchemy import inspect
        with self.engine.begin() as db:
            db.execute(text("CREATE TABLE remote_sessions (id VARCHAR(36) PRIMARY KEY, created_by VARCHAR(80) NOT NULL)"))
            db.execute(text("INSERT INTO remote_sessions VALUES ('fixture', 'historical actor')"))
        self.assertTrue(add_recording_deletion_timestamp(self.engine))
        self.assertFalse(add_recording_deletion_timestamp(self.engine))
        column = next(item for item in inspect(self.engine).get_columns("remote_sessions") if item["name"] == "recording_deleted_at")
        self.assertTrue(column["nullable"])
        with self.engine.connect() as db:
            self.assertEqual(tuple(db.execute(text("SELECT id, created_by, recording_deleted_at FROM remote_sessions")).one()),
                             ("fixture", "historical actor", None))

    async def test_long_username_schema_upgrade_preserves_history_and_is_idempotent(self):
        from app.schema_migrations import widen_remote_session_actor
        self.assertEqual(m.RemoteSession.__table__.c.created_by.type.length, 80)
        with self.engine.begin() as db:
            db.execute(text("CREATE TABLE remote_sessions (id VARCHAR(36) PRIMARY KEY, created_by VARCHAR(36) NOT NULL)"))
            db.execute(text("INSERT INTO remote_sessions VALUES ('old', 'old-operator')"))
        username = "operator." + "x" * 59 + "@example.org"
        self.assertEqual(len(username), 80)
        with self.assertRaises(DataError), self.engine.begin() as db:
            db.execute(text("INSERT INTO remote_sessions VALUES ('long', :actor)"), {"actor": username})
        self.assertTrue(widen_remote_session_actor(self.engine))
        self.assertFalse(widen_remote_session_actor(self.engine))
        with self.engine.begin() as db:
            db.execute(text("INSERT INTO remote_sessions VALUES ('long', :actor)"), {"actor": username})
            rows = dict(db.execute(text("SELECT id, created_by FROM remote_sessions")).all())
        self.assertEqual(rows, {"old": "old-operator", "long": username})
