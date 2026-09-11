"""Small, idempotent PostgreSQL upgrades for existing installations."""

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine


def detach_recording_history_users(engine: Engine) -> int:
    """Keep immutable actor IDs/names after account deletion, without user FKs.

    create_all does not modify existing constraints. Only the two legacy user
    references are removed; no rows, columns, or recording files are touched.
    SQLite is used only by the existing disposable unit-test harness.
    """
    if engine.dialect.name != "postgresql":
        return 0
    removed = 0
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL lock_timeout = '5s'"))
        connection.execute(text("SELECT pg_advisory_xact_lock(741603109)"))
        inspector = inspect(connection)
        quote = connection.dialect.identifier_preparer.quote
        for constraint in inspector.get_foreign_keys("recording_deletion_requests"):
            if (
                constraint["constrained_columns"] in (["requested_by"], ["approved_by"])
                and constraint["referred_table"] == "users"
                and constraint["referred_columns"] == ["id"]
                and constraint.get("referred_schema") in (None, inspector.default_schema_name)
            ):
                # Constraint names come from the catalog, not an HTTP payload.
                name = quote(constraint["name"])
                connection.execute(text(f'ALTER TABLE recording_deletion_requests DROP CONSTRAINT {name}'))
                removed += 1
    return removed


def widen_remote_session_actor(engine: Engine) -> bool:
    """The session actor is a username snapshot, matching User.username(80)."""
    if engine.dialect.name != "postgresql":
        return False
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL lock_timeout = '5s'"))
        connection.execute(text("SELECT pg_advisory_xact_lock(741603110)"))
        columns = inspect(connection).get_columns("remote_sessions")
        actor = next(column for column in columns if column["name"] == "created_by")
        length = getattr(actor["type"], "length", None)
        if length is None or length >= 80:
            return False
        connection.execute(text("ALTER TABLE remote_sessions ALTER COLUMN created_by TYPE VARCHAR(80)"))
        return True
