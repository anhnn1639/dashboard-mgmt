"""Ephemeral, recording-gated browser desktops on a private RFB transport.

No vault access, persistent profiles, Docker socket, shell, or browser chrome.
The API controls a short lease; no target request or input before activation.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import io
import ipaddress
import os
import re
import secrets
import socket
import struct
import time
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from PIL import Image, ImageDraw, ImageFont
from playwright.async_api import async_playwright
from pydantic import BaseModel, ConfigDict, Field, field_validator


def origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if (parsed.scheme not in {"https", "wss"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or "\\" in url or any(ord(c) < 33 for c in url)):
        raise ValueError("invalid target")
    host = parsed.hostname.lower()
    if not re.fullmatch(r"[a-z0-9.-]+|[0-9a-f:]+", host):
        raise ValueError("invalid hostname")
    return ("https", host, parsed.port or 443)


def allowed_url(url: str, target: str) -> bool:
    try:
        return origin(url) == origin(target)
    except ValueError:
        return False


def safe_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return safe_ip(str(ip.ipv4_mapped))
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


async def pinned_address(url: str) -> str:
    _, host, port = origin(url)
    answers = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = {item[4][0] for item in answers}
    if not ips or not all(safe_ip(ip) for ip in ips):
        raise ValueError("unsafe target")
    # The actual browser DNS is pinned for the entire session, including WSS.
    return sorted(ips, key=lambda ip: (":" in ip, ip))[0]


class CreateSession(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: UUID
    target_url: str = Field(max_length=2048)
    width: int = Field(default=1440, ge=800, le=1920)
    height: int = Field(default=900, ge=600, le=1080)

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, value):
        origin(value)
        if not value.startswith("https://") or urlsplit(value).fragment:
            raise ValueError("HTTPS target required")
        return value


def authenticate(authorization: str = Header(default="")):
    secret = os.environ.get("GUACAMOLE_JSON_SECRET", "")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", secret):
        raise HTTPException(503, "Service configuration required")
    expected = "Bearer " + hashlib.sha256(("tram-web-console:" + secret).encode()).hexdigest()
    if not hmac.compare_digest(authorization, expected):
        raise HTTPException(401, "Authentication required")


def challenge_response(password: str, challenge: bytes) -> bytes:
    # RFB's standard VNC authentication is DES with bit-reversed key bytes.
    # Only used on the unexposed Docker session network, single-use and expiring.
    key = bytes(int(f"{b:08b}"[::-1], 2) for b in password.encode("ascii")[:8])
    cipher = Cipher(TripleDES(key * 3), modes.ECB()).encryptor()
    return cipher.update(challenge) + cipher.finalize()


KEYS = {0xff08: "Backspace", 0xff09: "Tab", 0xff0d: "Enter", 0xff1b: "Escape",
        0xffff: "Delete", 0xff50: "Home", 0xff57: "End", 0xff51: "ArrowLeft",
        0xff52: "ArrowUp", 0xff53: "ArrowRight", 0xff54: "ArrowDown",
        0xff55: "PageUp", 0xff56: "PageDown", 0xff63: "Insert",
        0xffe1: "Shift", 0xffe2: "Shift", 0xffe3: "Control", 0xffe4: "Control",
        0xffe9: "Alt", 0xffea: "Alt"}


class Desktop:
    def __init__(self, payload: CreateSession):
        self.id = str(payload.session_id)
        self.url = payload.target_url
        self.width, self.height = payload.width, payload.height
        self.password = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(8))
        self.status, self.reason = "waiting", ""
        self.created = time.monotonic()
        self.deadline = self.created + 120
        self.listener = self.writer = self.browser = self.context = self.page = None
        self.client_task = self.navigation_task = None
        self.frame_requested = asyncio.Event()
        self.pixel_format = (32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
        self.buttons = 0
        self.keys = set()
        self.clipboard = ""
        self.input_lock = asyncio.Lock()
        self.notice = "Đang chuẩn bị ghi hình kiểm toán. Vui lòng chờ…"

    async def start(self, playwright):
        ip = await pinned_address(self.url)
        host = origin(self.url)[1]
        mapped = f"[{ip}]" if ":" in ip else ip
        self.browser = await playwright.chromium.launch(headless=True, chromium_sandbox=True,
            args=[f"--host-resolver-rules=MAP {host} {mapped}, MAP * ~NOTFOUND",
                  "--no-proxy-server", "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"],
            env={k: v for k, v in os.environ.items() if k not in {
                "GUACAMOLE_JSON_SECRET", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}})
        self.context = await self.browser.new_context(viewport={"width": self.width, "height": self.height - 28},
            accept_downloads=False, ignore_https_errors=False, service_workers="block")
        self.context.set_default_timeout(3000)
        self.context.set_default_navigation_timeout(15000)
        await self.context.route("**/*", self.route)
        await self.context.route_web_socket("**/*", self.route_socket)
        # Block WebRTC/WebTransport's non-HTTP transports before any site script.
        await self.context.add_init_script("""for (const k of ['RTCPeerConnection','webkitRTCPeerConnection','WebTransport']) {
            Object.defineProperty(globalThis,k,{value:undefined,writable:false,configurable:false}); }
            window.open = () => null;""")
        self.page = await self.context.new_page()
        self.page.on("dialog", lambda dialog: dialog.dismiss())
        self.page.on("download", lambda download: download.cancel())
        self.context.on("page", self.extra_page)
        self.listener = await asyncio.start_server(self.accept, "0.0.0.0", 0, limit=131072)
        return self.listener.sockets[0].getsockname()[1]

    async def extra_page(self, page):
        if page != self.page:
            await page.close()

    async def route(self, route):
        if self.status == "active" and allowed_url(route.request.url, self.url):
            await route.continue_()
        else:
            self.notice = "Đã chặn địa chỉ ngoài console. Liên hệ quản trị viên nếu cần đăng nhập SSO."
            await route.abort("blockedbyclient")

    async def route_socket(self, websocket):
        if self.status == "active" and allowed_url(websocket.url, self.url):
            websocket.connect_to_server()
        else:
            await websocket.close()

    async def activate(self):
        if self.status != "connected":
            raise HTTPException(409, "Recording transport is not connected")
        self.status = "active"
        self.deadline = time.monotonic() + 15
        self.notice = ""
        # Return promptly so that the API can renew the recording lease while
        # a slow internal site loads. Browser navigation is independently bounded.
        self.navigation_task = asyncio.create_task(self.navigate())

    async def navigate(self):
        try:
            await self.page.goto(self.url, wait_until="domcontentloaded")
        except Exception:
            self.notice = "Không mở được website. Kiểm tra kết nối mạng, chứng thư HTTPS hoặc địa chỉ SSO."

    async def stop(self, reason="closed"):
        if self.status in {"closed", "failed"}:
            return
        self.status = "closed" if reason == "closed" else "failed"
        self.reason = reason
        if self.listener:
            self.listener.close()
        if self.writer:
            self.writer.close()
        if self.navigation_task:
            self.navigation_task.cancel()
            await asyncio.gather(self.navigation_task, return_exceptions=True)
        if self.browser:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.browser.close(), 5)
        self.clipboard = ""
        self.password = ""
        self.deadline = time.monotonic() + 60

    async def accept(self, reader, writer):
        if self.status != "waiting" or self.writer:
            writer.close()
            return
        self.writer = writer
        self.client_task = asyncio.current_task()
        self.listener.close()  # one transport connection per session
        frame_task = None
        try:
            async with asyncio.timeout(10):
                writer.write(b"RFB 003.008\n")
                await writer.drain()
                if await reader.readexactly(12) != b"RFB 003.008\n":
                    raise ValueError("unsupported RFB")
                writer.write(b"\x01\x02")
                await writer.drain()
                if await reader.readexactly(1) != b"\x02":
                    raise ValueError("VNC authentication required")
                challenge = secrets.token_bytes(16)
                writer.write(challenge)
                await writer.drain()
                if not hmac.compare_digest(await reader.readexactly(16), challenge_response(self.password, challenge)):
                    writer.write(struct.pack(">I", 1))
                    await writer.drain()
                    raise ValueError("authentication failed")
                writer.write(struct.pack(">I", 0))
                await writer.drain()
                await reader.readexactly(1)
                title = b"Tram Van Hanh - recorded web console"
                writer.write(struct.pack(">HH", self.width, self.height)
                    + struct.pack(">BBBBHHHBBB3x", *self.pixel_format)
                    + struct.pack(">I", len(title)) + title)
                await writer.drain()
                self.status = "connected"
            frame_task = asyncio.create_task(self.frames(writer))
            while self.status in {"connected", "active"}:
                kind = (await reader.readexactly(1))[0]
                if kind == 0:
                    await reader.readexactly(3)
                    fmt = struct.unpack(">BBBBHHHBBB3x", await reader.readexactly(16))
                    if fmt[:4] not in {(32, 24, 0, 1), (32, 24, 1, 1)} or fmt[4:7] != (255, 255, 255) or sorted(fmt[7:]) != [0, 8, 16]:
                        raise ValueError("unsupported pixel format")
                    self.pixel_format = fmt
                elif kind == 2:
                    _, count = struct.unpack(">BH", await reader.readexactly(3))
                    if count > 256:
                        raise ValueError("too many encodings")
                    await reader.readexactly(count * 4)  # Raw encoding always supported by RFB.
                elif kind == 3:
                    await reader.readexactly(9)
                    self.frame_requested.set()
                elif kind == 4:
                    down, keysym = struct.unpack(">B2xI", await reader.readexactly(7))
                    if self.status == "active":
                        async with self.input_lock:
                            await self.key(keysym, bool(down))
                elif kind == 5:
                    mask, x, y = struct.unpack(">BHH", await reader.readexactly(5))
                    if self.status == "active":
                        async with self.input_lock:
                            await self.mouse(mask, x, y)
                elif kind == 6:
                    length = struct.unpack(">3xI", await reader.readexactly(7))[0]
                    if length > 65536:
                        raise ValueError("clipboard limit")
                    value = await reader.readexactly(length)
                    if self.status == "active":
                        self.clipboard = value.decode("utf-8", errors="replace")
                else:
                    raise ValueError("unsupported RFB message")
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception:
            self.reason = "transport-failed"
        finally:
            if frame_task:
                frame_task.cancel()
                await asyncio.gather(frame_task, return_exceptions=True)
            await self.stop(self.reason or "closed")
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def key(self, keysym, down):
        key = KEYS.get(keysym)
        if key is None:
            point = keysym & 0xffffff if keysym & 0xff000000 == 0x01000000 else keysym
            if 32 <= point <= 0x10ffff and not 0xd800 <= point <= 0xdfff and (point < 0xff00 or point > 0xffff):
                key = chr(point)
            else:
                return
        if down:
            self.keys.add(key)
            if (key.lower() == "v" and "Control" in self.keys) or (key == "Insert" and "Shift" in self.keys):
                await self.page.keyboard.insert_text(self.clipboard)
                return
            await self.page.keyboard.down(key)
        else:
            self.keys.discard(key)
            await self.page.keyboard.up(key)

    async def mouse(self, mask, x, y):
        if y < 28:
            return
        await self.page.mouse.move(min(x, self.width - 1), min(y - 28, self.height - 29))
        for bit, name in ((1, "left"), (2, "middle"), (4, "right")):
            if bool(mask & bit) != bool(self.buttons & bit):
                await (self.page.mouse.down(button=name) if mask & bit else self.page.mouse.up(button=name))
        if mask & 8:
            await self.page.mouse.wheel(0, -120)
        if mask & 16:
            await self.page.mouse.wheel(0, 120)
        self.buttons = mask

    async def frames(self, writer):
        try:
            while self.status in {"connected", "active"}:
                await self.frame_requested.wait()
                self.frame_requested.clear()
                if self.status == "active":
                    data = await self.page.screenshot(type="png", timeout=4000)
                    content = Image.open(io.BytesIO(data)).convert("RGB")
                    frame = Image.new("RGB", (self.width, self.height), "#11223b")
                    frame.paste(content, (0, 28))
                else:
                    frame = Image.new("RGB", (self.width, self.height), "#11223b")
                # A visible changing audit clock ensures idle sessions continue
                # producing frames, allowing the API to detect a stalled recorder.
                draw = ImageDraw.Draw(frame)
                draw.rectangle((0, 0, self.width, 24), fill="#11223b")
                text = self.notice or "ĐANG GHI HÌNH · Web console qua Trạm Vận Hành · " + time.strftime("%H:%M:%S UTC", time.gmtime())
                try:
                    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
                except OSError:
                    font = ImageFont.load_default()
                draw.text((8, 3), text, fill="white", font=font)
                # Slightly changing pixel also drives progress before activation.
                draw.point((self.width - 1, 0), fill=(int(time.monotonic() * 2) % 255, 20, 30))
                fmt = self.pixel_format
                rgb = frame.tobytes()
                raw = bytearray(self.width * self.height * 4)
                for channel, shift in enumerate(fmt[7:]):
                    offset = shift // 8 if fmt[2] == 0 else 3 - shift // 8
                    raw[offset::4] = rgb[channel::3]
                writer.write(struct.pack(">BBHHHHHi", 0, 0, 1, 0, 0, self.width, self.height, 0) + raw)
                await asyncio.wait_for(writer.drain(), 5)
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.reason = "capture-failed"
            writer.close()


desktops: dict[str, Desktop] = {}
playwright = None
creation_lock = asyncio.Lock()


async def sweep():
    while True:
        for identifier, desktop in list(desktops.items()):
            if time.monotonic() > desktop.deadline:
                if desktop.status in {"closed", "failed"}:
                    desktops.pop(identifier, None)
                else:
                    await desktop.stop("lease-expired")
        await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(_app):
    global playwright
    async with async_playwright() as playwright:
        task = asyncio.create_task(sweep())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await asyncio.gather(*(d.stop("service-stopped") for d in list(desktops.values())), return_exceptions=True)
            desktops.clear()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(RequestValidationError)
async def validation_error(_request, _exc):
    return JSONResponse(status_code=422, content={"detail": "Invalid session request"})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/sessions", dependencies=[Depends(authenticate)])
async def create(payload: CreateSession):
    identifier = str(payload.session_id)
    async with creation_lock:
        alive = [d for d in desktops.values() if d.status not in {"closed", "failed"}]
        if identifier in desktops or len(alive) >= 8 or sum(origin(d.url) == origin(payload.target_url) for d in alive) >= 4:
            raise HTTPException(409, "Session capacity reached")
        desktop = Desktop(payload)
        desktops[identifier] = desktop
        try:
            async with asyncio.timeout(25):
                port = await desktop.start(playwright)
            return {"port": port, "password": desktop.password, "status": desktop.status}
        except asyncio.CancelledError:
            await desktop.stop("prepare-cancelled")
            raise
        except Exception:
            await desktop.stop("prepare-failed")
            raise HTTPException(503, "Cannot prepare browser") from None


def get_desktop(identifier: UUID):
    item = desktops.get(str(identifier))
    if item is None:
        raise HTTPException(404, "Session not found")
    return item


@app.get("/sessions/{identifier}", dependencies=[Depends(authenticate)])
def status(identifier: UUID):
    item = get_desktop(identifier)
    return {"status": item.status, "reason": item.reason}


@app.post("/sessions/{identifier}/activate", dependencies=[Depends(authenticate)])
async def activate(identifier: UUID):
    await get_desktop(identifier).activate()
    return {"status": "active"}


@app.post("/sessions/{identifier}/lease", dependencies=[Depends(authenticate)])
def lease(identifier: UUID):
    item = get_desktop(identifier)
    if item.status != "active" or time.monotonic() > item.deadline or time.monotonic() - item.created > 3600:
        raise HTTPException(409, "Session lease expired")
    item.deadline = time.monotonic() + 15
    return {"status": item.status}


@app.delete("/sessions/{identifier}", dependencies=[Depends(authenticate)])
async def close(identifier: UUID):
    item = desktops.get(str(identifier))
    if item:
        await item.stop()
    return {"status": "closed"}
