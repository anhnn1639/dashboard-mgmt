"""Authenticated client and recording-gated lifetime for remote web browsers.

Only ephemeral transport state lives here. Sessions, grants and audit history are
owned by PostgreSQL in main.py. The worker never receives dashboard cookies.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener


class WebSessionError(Exception):
    pass


class WebSessionHub:
    def __init__(self, base_url: str, secret: Callable[[], str]):
        self.base_url = base_url.rstrip("/")
        self.secret = secret
        self.tasks: dict[str, asyncio.Task] = {}

    @property
    def configured(self) -> bool:
        return bool(self.base_url and re.fullmatch(r"[0-9a-fA-F]{32}", self.secret()))

    async def call(self, method: str, path: str, payload: dict | None = None) -> dict:
        if not self.configured:
            raise WebSessionError("unavailable")
        token = hashlib.sha256(("tram-web-console:" + self.secret()).encode()).hexdigest()

        def send():
            request = Request(self.base_url + path, method=method,
                              data=json.dumps(payload).encode() if payload is not None else None,
                              headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
            # No environment proxy and no redirects: never forward the broker
            # capability or an activation credential to another service.
            from urllib.request import HTTPRedirectHandler

            class NoRedirect(HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            try:
                with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=30 if path == "/sessions" else 5) as response:
                    body = response.read(16385)
                    if len(body) > 16384:
                        raise WebSessionError("invalid-response")
                    result = json.loads(body)
                    if not isinstance(result, dict):
                        raise WebSessionError("invalid-response")
                    return result
            except (HTTPError, URLError, OSError, ValueError) as exc:
                # Upstream content can contain target URLs and credentials.
                raise WebSessionError("unavailable") from exc

        return await asyncio.to_thread(send)

    async def prepare(self, session_id: str, target_url: str, width: int, height: int, *, ignore_https_errors: bool = False, allowed_origins: list[str] | None = None) -> dict:
        result = await self.call("POST", "/sessions", {"session_id": session_id, "target_url": target_url,
                                                       "width": width, "height": height, "ignore_https_errors": ignore_https_errors, "allowed_origins": allowed_origins or []})
        if (type(result.get("port")) is not int or not 1024 <= result["port"] <= 65535
                or not isinstance(result.get("password"), str)
                or not re.fullmatch(r"[A-Za-z0-9]{8}", result["password"])):
            await self.stop_remote(session_id)
            raise WebSessionError("invalid-response")
        return result

    async def stop_remote(self, session_id: str) -> None:
        try:
            await self.call("DELETE", "/sessions/" + session_id)
        except WebSessionError:
            # Active worker leases expire independently if it is unreachable.
            pass

    def watch(self, session_id: str, recording: Callable[[], Path | None],
              authorize: Callable[[], bool], activate: Callable[[], Awaitable[None]],
              closed: Callable[[str, str], Awaitable[None]]) -> None:
        self.tasks[session_id] = asyncio.create_task(self._watch(session_id, recording, authorize, activate, closed))

    async def _watch(self, session_id, recording, authorize, activate, closed):
        reason = "web-service-failed"
        started = time.monotonic()
        active = False
        last_size = 0
        progressed = started
        try:
            while time.monotonic() - started < 3600:
                if not authorize():
                    reason = "web-access-revoked"
                    break
                state = await self.call("GET", "/sessions/" + session_id)
                if state.get("status") in {"closed", "failed"}:
                    reason = "closed" if state["status"] == "closed" else "web-browser-failed"
                    break
                path = recording()
                size = path.stat().st_size if path else 0
                if not active:
                    if size > 0 and state.get("status") == "connected":
                        await activate()
                        active = True
                        last_size, progressed = size, time.monotonic()
                    elif time.monotonic() - started > 120:
                        reason = "web-recording-not-started"
                        break
                else:
                    if size > last_size:
                        last_size, progressed = size, time.monotonic()
                    if not size or size < last_size or time.monotonic() - progressed > 10:
                        reason = "web-recording-stopped"
                        break
                    await self.call("POST", "/sessions/" + session_id + "/lease", {})
                await asyncio.sleep(1)
            else:
                reason = "web-session-expired"
        except asyncio.CancelledError:
            reason = "web-service-stopped"
            raise
        except Exception:
            # Fail closed on recording I/O, database or broker failure.
            reason = "web-service-failed"
        finally:
            await self.stop_remote(session_id)
            try:
                await closed(session_id, reason)
            finally:
                self.tasks.pop(session_id, None)

    async def shutdown(self) -> None:
        tasks = list(self.tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
