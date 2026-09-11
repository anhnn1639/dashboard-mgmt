"""Short PostgreSQL operations for the recorded browser's control loop."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TypeVar

from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool
from sqlalchemy.orm import Session

T = TypeVar("T")
WEB_DATABASE_SECONDS = 5


async def run_postgres(url: URL, work: Callable[[Session], T]) -> T:
    # A dedicated async connection avoids both the synchronous API pool and
    # blocking worker threads surviving a timeout. Retain URL search_path/TLS.
    options = str(url.query.get("options", ""))
    bounded = url.update_query_dict({"options": options + " -c statement_timeout=2000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=4000"})
    engine = create_async_engine(bounded, poolclass=NullPool, connect_args={"connect_timeout": 2})
    try:
        async with asyncio.timeout(WEB_DATABASE_SECONDS):
            async with AsyncSession(engine, expire_on_commit=False) as db:
                return await db.run_sync(work)
    finally:
        await engine.dispose()
