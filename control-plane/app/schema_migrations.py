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


def add_recording_deletion_timestamp(engine: Engine) -> bool:
    """Keep session/audit history while hiding recordings removed successfully."""
    if engine.dialect.name != "postgresql":
        return False
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL lock_timeout = '5s'"))
        connection.execute(text("SELECT pg_advisory_xact_lock(741603111)"))
        if any(column["name"] == "recording_deleted_at"
               for column in inspect(connection).get_columns("remote_sessions")):
            return False
        connection.execute(text("ALTER TABLE remote_sessions ADD COLUMN recording_deleted_at TIMESTAMPTZ NULL"))
        return True


REUSABLE_PACKAGE_COLUMNS = (
    ("reusable", "BOOLEAN NOT NULL DEFAULT FALSE"),
    ("release_version", "VARCHAR(40) NOT NULL DEFAULT ''"),
    ("linux_profile", "VARCHAR(20) NOT NULL DEFAULT ''"),
    ("claim_count", "INTEGER NOT NULL DEFAULT 0"),
    ("max_claims", "INTEGER NULL"),
    ("revoked_at", "TIMESTAMPTZ NULL"),
    ("revoked_by", "VARCHAR(80) NOT NULL DEFAULT ''"),
)

SERVER_CHANNEL_COLUMNS = (
    ("last_checkin_at", "TIMESTAMPTZ NULL"),
    ("channel_error", "VARCHAR(120) NOT NULL DEFAULT ''"),
    ("channel_error_at", "TIMESTAMPTZ NULL"),
    ("clock_offset_ms", "INTEGER NULL"),
    ("clock_status", "VARCHAR(30) NOT NULL DEFAULT ''"),
    ("clock_error", "VARCHAR(240) NOT NULL DEFAULT ''"),
    ("clock_stepped_at", "TIMESTAMPTZ NULL"),
    ("clock_step_ms", "INTEGER NULL"),
)


def add_agent_package_and_channel_columns(engine: Engine) -> list[str]:
    """Add multi-use installer state and Agent channel diagnostics.

    Existing installers keep their single-use semantics (reusable = false).
    Servers enrolled before this column existed only ever updated last_seen
    from 9443 check-ins after enrollment, so last_seen is the best backfill.
    """
    if engine.dialect.name != "postgresql":
        return []
    added: list[str] = []
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL lock_timeout = '5s'"))
        connection.execute(text("SELECT pg_advisory_xact_lock(741603112)"))
        inspector = inspect(connection)
        for table, columns in (("agent_bootstrap_packages", REUSABLE_PACKAGE_COLUMNS), ("servers", SERVER_CHANNEL_COLUMNS)):
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, definition in columns:
                if name in existing:
                    continue
                # Names and definitions are module constants, never user input.
                connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))
                added.append(f"{table}.{name}")
        if "servers.last_checkin_at" in added:
            connection.execute(text("UPDATE servers SET last_checkin_at = last_seen WHERE last_checkin_at IS NULL"))
    return added
