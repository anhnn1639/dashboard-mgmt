"""Ephemeral, recording-gated browser desktops on a private RFB transport.

No vault access, persistent profiles, Docker socket, shell, or browser chrome.
The API controls a short lease; no target request or input before activation.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import io
import logging
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
from playwright.async_api import Error as BrowserError, TimeoutError as BrowserTimeoutError, async_playwright
from pydantic import BaseModel, ConfigDict, Field, field_validator
from restricted_proxy import PinnedProxy
from auto_login import ActivationRequest, SavedAccountLogin


def origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if (parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or "\\" in url or any(ord(c) < 33 for c in url)):
        raise ValueError("invalid target")
    host = parsed.hostname.lower()
    if not re.fullmatch(r"[a-z0-9.-]+|[0-9a-f:]+", host):
        raise ValueError("invalid hostname")
    scheme = "https" if parsed.scheme in {"https", "wss"} else "http"
    port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return (scheme, host, port)


def origin_text(value: tuple[str, str, int]) -> str:
    scheme, host, port = value
    return f"{scheme}://{'[' + host + ']' if ':' in host else host}:{port}"


def validate_web_target(value: str) -> str:
    origin(value)
    if not value.startswith(("http://", "https://")) or urlsplit(value).fragment:
        raise ValueError("HTTP or HTTPS target required")
    return value


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
    # The CONNECT transport uses this IP for the entire session, including WSS.
    return sorted(ips, key=lambda ip: (":" in ip, ip))[0]


BROWSER_ARGS = ["--proxy-bypass-list=<-loopback>", "--disable-quic",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]
BROWSER_ENV = {"HOME", "PATH", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT", "TEMP", "TMP"}
# Block WebRTC/WebTransport's non-HTTP transports before any site script.
INIT_SCRIPT = """for (const k of ['RTCPeerConnection','webkitRTCPeerConnection','WebTransport']) {
            Object.defineProperty(globalThis,k,{value:undefined,writable:false,configurable:false}); }
            window.open = () => null;"""
NAVIGATION_NOTICES = {
    "certificate": "Website từ chối chứng thư HTTPS. Kiểm tra dịch vụ hoặc yêu cầu chứng thư phía máy khách.",
    "timeout": "Website tải quá lâu. Kiểm tra dịch vụ website rồi mở lại phiên.",
    "blocked-origin": "Địa chỉ chuyển hướng chưa được phép. Administrator cần thêm địa chỉ / cổng SSO trong Sửa kết nối.",
    "tls": "Không thương lượng được HTTPS. Kiểm tra giao thức TLS và cổng của website.",
    "connection": "Không kết nối được website từ dịch vụ trình duyệt. Kiểm tra URL, DNS và kết nối của container.",
}


async def launch_browser(playwright, proxy):
    # One hardened launch path for recorded sessions and for origin discovery.
    return await playwright.chromium.launch(headless=True, chromium_sandbox=True, timeout=20000,
        proxy=proxy, args=BROWSER_ARGS,
        env={k: v for k, v in os.environ.items() if k in BROWSER_ENV})


def navigation_error_code(exc: Exception, blocked_destination: bool) -> str:
    # Never echo exception text: it can contain SAML tokens or URLs.
    error = re.search(r"net::(ERR_[A-Z0-9_]+)", str(exc))
    code = error.group(1) if error else ""
    if code.startswith("ERR_CERT_"):
        return "certificate"
    if isinstance(exc, BrowserTimeoutError):
        return "timeout"
    if blocked_destination:
        return "blocked-origin"
    if code.startswith("ERR_SSL_"):
        return "tls"
    return "connection"


class CreateSession(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: UUID
    target_url: str = Field(max_length=2048)
    allowed_origins: list[str] = Field(default_factory=list, max_length=16)
    # Backward compatibility only. Certificate handling is automatic within
    # the unchanged configured-origin boundary of each recorded browser.
    ignore_https_errors: bool = Field(default=False, strict=True, exclude=True)
    width: int = Field(default=1440, ge=800, le=1920)
    height: int = Field(default=900, ge=600, le=1080)

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, value):
        return validate_web_target(value)

    @field_validator("allowed_origins")
    @classmethod
    def validate_origins(cls, values):
        for value in values:
            origin(value)
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or len(value) > 256:
                raise ValueError("Only explicit HTTP/HTTPS origins are accepted")
        return values


class DiscoverRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_url: str = Field(max_length=2048)

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, value):
        return validate_web_target(value)


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


DISCOVERY_LIMIT = 16
KEYS = {0xff08: "Backspace", 0xff09: "Tab", 0xff0d: "Enter", 0xff1b: "Escape",
        0xffff: "Delete", 0xff50: "Home", 0xff57: "End", 0xff51: "ArrowLeft",
        0xff52: "ArrowUp", 0xff53: "ArrowRight", 0xff54: "ArrowDown",
        0xff55: "PageUp", 0xff56: "PageDown", 0xff63: "Insert",
        0xffe1: "Shift", 0xffe2: "Shift", 0xffe3: "Control", 0xffe4: "Control",
        0xffe9: "Alt", 0xffea: "Alt"}


CAPTURE_ATTEMPT_SECONDS = 4
CAPTURE_RECOVERY_SECONDS = 8


class CaptureLeaseExpired(Exception):
    pass


class Desktop:
    def __init__(self, payload: CreateSession):
        self.id = str(payload.session_id)
        self.url = payload.target_url
        self.ignore_https_errors = True
        self.navigation_error = ""
        self.allowed_origins = frozenset([origin(self.url), *(origin(value) for value in payload.allowed_origins)])
        self.destinations = {}
        self.destination_lock = asyncio.Lock()
        self.width, self.height = payload.width, payload.height
        self.password = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(8))
        self.status, self.reason = "waiting", ""
        self.created = time.monotonic()
        self.deadline = self.created + 120
        self.listener = self.writer = self.browser = self.context = self.page = None
        self.client_task = self.navigation_task = self.proxy = None
        self.capture = None
        self.capture_recovering = False
        self.website_frame_ready = False
        self.document_revision = 0
        self.login = None
        self.frame_requested = asyncio.Event()
        self.pixel_format = (32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
        self.buttons = 0
        self.keys = set()
        self.clipboard = ""
        self.input_lock = asyncio.Lock()
        # Origins this session navigated to but may not reach, reported to the
        # API as Administrator suggestions. Origins only, never a path or token.
        self.blocked_origins: list[str] = []
        self.notice = "Đang chuẩn bị ghi hình kiểm toán. Vui lòng chờ…"

    def input_enabled(self):
        now = time.monotonic()
        return self.status == "active" and now < self.deadline and now - self.created < 3600

    def interaction_enabled(self):
        # Page loading still uses the normal network lease while capture recovers.
        return self.input_enabled() and not self.capture_recovering

    def automation_enabled(self):
        return self.interaction_enabled() and self.website_frame_ready

    def frame_navigated(self, frame):
        if frame == self.page.main_frame:
            self.document_revision += 1
            self.website_frame_ready = False

    async def release_held_input(self):
        # Releases arriving during capture recovery were intentionally deferred.
        # Clear held modifiers/buttons after fresh pixels reach the recorder,
        # before accepting any new input, so Ctrl/drag cannot remain stuck.
        async with asyncio.timeout(1):
            async with self.input_lock:
                for key in tuple(self.keys):
                    await self.page.keyboard.up(key)
                    self.keys.discard(key)
                for bit, name in ((1, "left"), (2, "middle"), (4, "right")):
                    if self.buttons & bit:
                        await self.page.mouse.up(button=name)
                self.buttons = 0

    async def capture_surface(self):
        # Before the first paint Chromium may report no surface immediately;
        # a busy renderer instead times out. Recover only these transient cases
        # within the API's unchanged 10s recording-stall watchdog. Never emit
        # old frames or an artificial audit clock during this interval.
        async with asyncio.timeout(CAPTURE_RECOVERY_SECONDS):
            while True:
                if not self.input_enabled():
                    raise CaptureLeaseExpired()
                try:
                    captured = await asyncio.wait_for(self.capture.send("Page.captureScreenshot", {
                        "format": "png", "fromSurface": True, "captureBeyondViewport": False,
                    }), CAPTURE_ATTEMPT_SECONDS)
                    if not self.input_enabled():
                        raise CaptureLeaseExpired()
                    return captured
                except (TimeoutError, BrowserError) as exc:
                    if isinstance(exc, BrowserError) and "Unable to capture screenshot" not in str(exc):
                        raise
                    if not self.capture_recovering:
                        logging.getLogger(__name__).warning("Web capture waiting for busy renderer; retrying within recording deadline")
                    self.capture_recovering = True
                    self.website_frame_ready = False
                    # Yield between transient no-surface errors instead of
                    # flooding Chromium while the first document is painting.
                    await asyncio.sleep(.1)

    async def start(self, playwright):
        ip = await pinned_address(self.url)
        scheme, host, port = origin(self.url)
        self.destinations[(scheme, host, port)] = ip
        self.proxy = PinnedProxy(host, port, ip, self.input_enabled, scheme=scheme, resolve=self.resolve_destination)
        self.browser = await launch_browser(playwright, await self.proxy.start())
        self.context = await self.browser.new_context(viewport={"width": self.width, "height": self.height - 28},
            accept_downloads=False, ignore_https_errors=self.ignore_https_errors, service_workers="block")
        self.context.set_default_timeout(3000)
        self.context.set_default_navigation_timeout(15000)
        await self.context.route("**/*", self.route)
        await self.context.route_web_socket("**/*", self.route_socket)
        await self.context.add_init_script(INIT_SCRIPT)
        self.page = await self.context.new_page()
        self.page.on("request", self.observe_request)
        self.page.on("framenavigated", self.frame_navigated)
        self.capture = await self.context.new_cdp_session(self.page)
        self.page.on("dialog", lambda dialog: dialog.dismiss())
        self.page.on("download", lambda download: download.cancel())
        self.context.on("page", self.extra_page)
        self.listener = await asyncio.start_server(self.accept, "0.0.0.0", 0, limit=131072)
        return self.listener.sockets[0].getsockname()[1]

    async def extra_page(self, page):
        if page != self.page:
            await page.close()

    async def resolve_destination(self, scheme, host, port):
        key = (scheme, host, port)
        # The set comes only from Administrator-approved PostgreSQL metadata.
        # Neither redirects nor page scripts can add an origin during a session.
        if key not in self.allowed_origins or not self.input_enabled():
            return None
        async with self.destination_lock:
            if key not in self.destinations:
                host_text = "[" + host + "]" if ":" in host else host
                try:
                    self.destinations[key] = await asyncio.wait_for(pinned_address(f"{scheme}://{host_text}:{port}"), 3)
                except (ValueError, OSError, TimeoutError):
                    return None
            return self.destinations[key] if self.input_enabled() else None

    def permitted(self, url):
        try:
            return origin(url) in self.allowed_origins
        except ValueError:
            return False

    def observe_request(self, request):
        # Only document navigations become Administrator suggestions, so page
        # scripts cannot propose an origin the website never redirected to.
        if not request.is_navigation_request() or self.permitted(request.url):
            return
        try:
            value = origin_text(origin(request.url))
        except ValueError:
            return
        if value not in self.blocked_origins and len(self.blocked_origins) < 8:
            self.blocked_origins.append(value)
        self.notice = self.blocked_notice()

    def blocked_notice(self):
        if self.blocked_origins:
            return f"Địa chỉ chuyển hướng chưa được phép: {self.blocked_origins[-1]}. Administrator thêm địa chỉ này trong Sửa kết nối."
        return NAVIGATION_NOTICES["blocked-origin"]

    async def route(self, route):
        if self.input_enabled() and self.permitted(route.request.url):
            await route.continue_()
        else:
            if self.input_enabled() and route.request.is_navigation_request():
                self.observe_request(route.request)
                self.navigation_error = "blocked-origin"
                self.notice = self.blocked_notice()
            await route.abort("blockedbyclient")

    async def route_socket(self, websocket):
        if self.input_enabled() and self.permitted(websocket.url):
            websocket.connect_to_server()
        else:
            await websocket.close()

    async def activate(self, credentials=None):
        if self.status != "connected" or time.monotonic() >= self.deadline or time.monotonic() - self.created >= 3600:
            raise HTTPException(409, "Recording transport is not connected")
        self.status = "active"
        self.deadline = time.monotonic() + 15
        self.notice = ""
        # Return promptly so that the API can renew the recording lease while
        # a slow internal site loads. Browser navigation is independently bounded.
        self.navigation_task = asyncio.create_task(self.navigate())
        if credentials is not None:
            self.login = SavedAccountLogin(self, credentials)
            self.login.start()

    async def navigate(self):
        self.navigation_error = ""
        if self.proxy:
            self.proxy.blocked_destination = False
        try:
            response = await self.page.goto(self.url, wait_until="domcontentloaded")
            if response is not None and response.status >= 400:
                self.navigation_error = "http-error"
                self.notice = f"Website trả lỗi HTTP {response.status}. Kiểm tra dịch vụ hoặc URL website."
        except Exception as exc:
            self.navigation_error = navigation_error_code(exc, bool(self.proxy and self.proxy.blocked_destination))
            self.notice = (self.blocked_notice() if self.navigation_error == "blocked-origin"
                           else NAVIGATION_NOTICES[self.navigation_error])

    async def stop(self, reason="closed"):
        if self.status in {"closed", "failed"}:
            return
        self.status = "closed" if reason == "closed" else "failed"
        if self.login:
            self.login.cancel()
            if self.login.task:
                await asyncio.gather(self.login.task, return_exceptions=True)
        self.reason = reason
        if self.proxy:
            await self.proxy.stop()
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
        if self.status != "waiting" or self.writer or time.monotonic() >= self.deadline:
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
                title = b"Operation Portal - recorded web console"
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
                    if self.input_enabled():
                        async with self.input_lock:
                            await self.key(keysym, bool(down))
                elif kind == 5:
                    mask, x, y = struct.unpack(">BHH", await reader.readexactly(5))
                    if self.input_enabled():
                        async with self.input_lock:
                            await self.mouse(mask, x, y)
                elif kind == 6:
                    length = struct.unpack(">3xI", await reader.readexactly(7))[0]
                    if length > 65536:
                        raise ValueError("clipboard limit")
                    value = await reader.readexactly(length)
                    if self.input_enabled():
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
        if down and self.login:
            self.login.cancel()
        if not self.interaction_enabled():
            return
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
        if mask & 7 and self.login:
            self.login.cancel()
        if not self.interaction_enabled() or y < 28:
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
        stage = "waiting"
        try:
            while self.status in {"connected", "active"}:
                await self.frame_requested.wait()
                self.frame_requested.clear()
                revision = None
                if self.status == "active":
                    # Record the actual composited surface while the website
                    # loads. Playwright page.screenshot waits for fonts/DOM
                    # readiness and can tear down healthy sessions on slow SSO.
                    stage = "capture"
                    revision = self.document_revision
                    captured_url = getattr(self.page, "url", "")
                    captured = await self.capture_surface()
                    stage = "decode"
                    data = base64.b64decode(captured["data"], validate=True)
                    content = Image.open(io.BytesIO(data)).convert("RGB")
                    frame = Image.new("RGB", (self.width, self.height), "#11223b")
                    frame.paste(content, (0, 28))
                else:
                    frame = Image.new("RGB", (self.width, self.height), "#11223b")
                # A visible changing audit clock ensures idle sessions continue
                # producing frames, allowing the API to detect a stalled recorder.
                draw = ImageDraw.Draw(frame)
                draw.rectangle((0, 0, self.width, 24), fill="#11223b")
                login_notice = ""
                if self.login and self.login.state in {"waiting-form", "waiting-password"}:
                    login_notice = "Đang tự đăng nhập bằng tài khoản đã chọn…"
                elif self.login and self.login.state == "manual-required":
                    login_notice = "Cần thao tác trong phiên: nhập OTP/CAPTCHA hoặc hoàn tất biểu mẫu đăng nhập."
                text = (self.notice or login_notice or "ĐANG GHI HÌNH · Web console qua Operation Portal") + " · " + time.strftime("%H:%M:%S UTC", time.gmtime())
                try:
                    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
                except OSError:
                    font = ImageFont.load_default()
                draw.text((8, 3), text, fill="white", font=font)
                # Slightly changing pixel also drives progress before activation.
                draw.point((self.width - 1, 0), fill=(int(time.monotonic() * 2) % 255, 20, 30))
                stage = "encode"
                fmt = self.pixel_format
                rgb = frame.tobytes()
                raw = bytearray(self.width * self.height * 4)
                for channel, shift in enumerate(fmt[7:]):
                    offset = shift // 8 if fmt[2] == 0 else 3 - shift // 8
                    raw[offset::4] = rgb[channel::3]
                stage = "transport"
                writer.write(struct.pack(">BBHHHHHi", 0, 0, 1, 0, 0, self.width, self.height, 0) + raw)
                await asyncio.wait_for(writer.drain(), 5)
                if self.status == "active" and revision is not None:
                    if self.capture_recovering:
                        stage = "input-reset"
                        await self.release_held_input()
                    self.capture_recovering = False
                    if (revision == self.document_revision and captured_url == getattr(self.page, "url", "")
                            and self.permitted(captured_url)):
                        self.website_frame_ready = True
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Sweep/stop may close Chromium while capture is in flight. Preserve
            # that existing reason rather than relabeling lease loss as capture.
            if self.status not in {"connected", "active"}:
                return
            if isinstance(exc, CaptureLeaseExpired) or (self.status == "active" and not self.input_enabled()):
                self.reason = "lease-expired"
            else:
                # Fixed stage/class only; browser exceptions can contain SSO URLs.
                logging.getLogger(__name__).warning("Web frame failed stage=%s kind=%s", stage, type(exc).__name__)
                self.reason = "capture-failed"
            self.capture_recovering = True
            self.website_frame_ready = False
            if self.login:
                self.login.cancel()
            writer.close()


class Discovery:
    """Open the configured URL once, with no input, no clipboard and no RFB
    transport, and report only the origins the website itself navigates to or
    loads. Nothing is typed or stored, results never contain a path, query or
    SAML token, and every destination keeps the unicast DNS/IP validation that
    recorded sessions use. The Administrator still decides what gets saved.
    """

    def __init__(self, url: str):
        self.url = url
        self.target = origin(url)
        self.navigation: list[tuple[str, str, int]] = []
        self.resources: list[tuple[str, str, int]] = []
        self.destinations: dict[tuple[str, str, int], str | None] = {}
        self.destination_lock = asyncio.Lock()
        self.page = None
        self.error = ""
        self.active = True
        self.settled = time.monotonic()
        self.pending_requests: dict = {}
        self.committed_navigations: set = set()

    def enabled(self) -> bool:
        return self.active

    async def resolve_destination(self, scheme, host, port):
        key = (scheme, host, port)
        async with self.destination_lock:
            if key not in self.destinations:
                if len(self.destinations) >= 1 + 2 * DISCOVERY_LIMIT:
                    return None
                host_text = "[" + host + "]" if ":" in host else host
                try:
                    self.destinations[key] = await asyncio.wait_for(pinned_address(f"{scheme}://{host_text}:{port}"), 3)
                except (ValueError, OSError, TimeoutError):
                    self.destinations[key] = None
            return self.destinations[key] if self.active else None

    def observe(self, url: str, navigation: bool) -> None:
        try:
            key = origin(url)
        except ValueError:
            return
        if navigation:
            self.settled = time.monotonic()
        if key == self.target:
            return
        if navigation:
            if key in self.resources:
                self.resources.remove(key)
            if key not in self.navigation and len(self.navigation) < DISCOVERY_LIMIT:
                self.navigation.append(key)
        elif key not in self.navigation and key not in self.resources and len(self.resources) < DISCOVERY_LIMIT:
            self.resources.append(key)

    def request_started(self, request):
        try:
            origin(request.url)
        except ValueError:
            return
        try:
            frame = request.frame
        except (AttributeError, BrowserError):
            frame = None
        self.pending_requests[request] = frame
        self.observe(request.url, request.is_navigation_request())

    def request_finished(self, request):
        self.committed_navigations.discard(request)
        if request in self.pending_requests:
            self.pending_requests.pop(request)
            self.settled = time.monotonic()

    def frame_navigated(self, frame):
        # Hash/history changes fire this event too, without replacing a document.
        navigation = next((request for request, source in self.pending_requests.items()
                           if source == frame and request.is_navigation_request()
                           and request not in self.committed_navigations
                           and request.url.split("#", 1)[0] == frame.url.split("#", 1)[0]), None)
        if navigation is None:
            return
        self.committed_navigations.add(navigation)
        # A fetch can resolve on headers and immediately navigate without its
        # body ever being consumed. Chromium may omit its completion event once
        # the document is replaced; it must not keep the new page "pending".
        # Retain the new document request until its own body completes.
        for request, source_frame in list(self.pending_requests.items()):
            if request is navigation:
                continue
            ancestor = source_frame
            while ancestor is not None and ancestor != frame:
                ancestor = ancestor.parent_frame
            if frame == self.page.main_frame or ancestor == frame:
                self.pending_requests.pop(request)
                self.committed_navigations.discard(request)
        self.settled = time.monotonic()

    async def extra_page(self, page):
        if page != self.page:
            await page.close()

    def result(self) -> dict:
        def reachable(key):
            return bool(self.destinations.get(key))

        return {"navigation": [origin_text(key) for key in self.navigation if reachable(key)],
                "resources": [origin_text(key) for key in self.resources if reachable(key)],
                "blocked": [origin_text(key) for key in self.navigation + self.resources if not reachable(key)][:DISCOVERY_LIMIT],
                "error": self.error}

    async def run(self, playwright) -> dict:
        proxy = browser = None
        try:
            scheme, host, port = self.target
            try:
                address = await asyncio.wait_for(pinned_address(self.url), 5)
            except (ValueError, OSError, TimeoutError):
                self.error = "connection"
                return self.result()
            self.destinations[self.target] = address
            proxy = PinnedProxy(host, port, address, self.enabled, scheme=scheme, resolve=self.resolve_destination)
            browser = await launch_browser(playwright, await proxy.start())
            context = await browser.new_context(viewport={"width": 1280, "height": 800},
                accept_downloads=False, ignore_https_errors=True, service_workers="block")
            context.set_default_timeout(3000)
            context.set_default_navigation_timeout(15000)
            await context.add_init_script(INIT_SCRIPT)
            self.page = await context.new_page()
            self.page.on("request", self.request_started)
            self.page.on("requestfinished", self.request_finished)
            self.page.on("requestfailed", self.request_finished)
            self.page.on("framenavigated", self.frame_navigated)
            self.page.on("websocket", lambda socket: self.observe(socket.url, False))
            self.page.on("dialog", lambda dialog: dialog.dismiss())
            self.page.on("download", lambda download: download.cancel())
            context.on("page", self.extra_page)
            deadline = time.monotonic() + 25
            try:
                response = await self.page.goto(self.url, wait_until="domcontentloaded")
                if response is not None and response.status >= 400:
                    self.error = "http-error"
            except Exception as exc:
                self.error = navigation_error_code(exc, proxy.blocked_destination)
            # A quiet gap does not mean that login discovery has finished:
            # bootstrap fetches, timers and meta refresh can navigate later.
            # Observe the whole bounded window, including those delayed hops.
            while time.monotonic() < deadline:
                await asyncio.sleep(min(0.25, deadline - time.monotonic()))
            if not self.error and (self.pending_requests or time.monotonic() - self.settled < 4):
                self.error = "timeout"
        finally:
            self.active = False
            if proxy:
                await proxy.stop()
            if browser:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(browser.close(), 5)
        return self.result()


desktops: dict[str, Desktop] = {}
playwright = None
creation_lock = asyncio.Lock()
discovery_lock = asyncio.Lock()


async def sweep():
    while True:
        expired = []
        for identifier, desktop in list(desktops.items()):
            if time.monotonic() >= desktop.deadline:
                if desktop.status in {"closed", "failed"}:
                    desktops.pop(identifier, None)
                else:
                    expired.append(desktop.stop("lease-expired"))
        await asyncio.gather(*expired, return_exceptions=True)
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


@app.post("/discover", dependencies=[Depends(authenticate)])
async def discover(payload: DiscoverRequest):
    if discovery_lock.locked():
        raise HTTPException(409, "Another discovery is running")
    async with discovery_lock:
        probe = Discovery(payload.target_url)
        try:
            async with asyncio.timeout(40):
                return await probe.run(playwright)
        except TimeoutError:
            return {**probe.result(), "error": "timeout"}
        except Exception:
            raise HTTPException(503, "Cannot prepare browser") from None


def get_desktop(identifier: UUID):
    item = desktops.get(str(identifier))
    if item is None:
        raise HTTPException(404, "Session not found")
    return item


@app.get("/sessions/{identifier}", dependencies=[Depends(authenticate)])
def status(identifier: UUID):
    item = get_desktop(identifier)
    return {"status": item.status, "reason": item.reason, "navigation_error": item.navigation_error,
            "blocked_origins": list(item.blocked_origins),
            "login_state": item.login.state if item.login else "manual"}


@app.post("/sessions/{identifier}/activate", dependencies=[Depends(authenticate)])
async def activate(identifier: UUID, payload: ActivationRequest):
    await get_desktop(identifier).activate(payload.credentials)
    return {"status": "active"}


@app.post("/sessions/{identifier}/lease", dependencies=[Depends(authenticate)])
def lease(identifier: UUID):
    item = get_desktop(identifier)
    if not item.input_enabled():
        raise HTTPException(409, "Session lease expired")
    item.deadline = min(time.monotonic() + 15, item.created + 3600)
    return {"status": item.status}


@app.delete("/sessions/{identifier}", dependencies=[Depends(authenticate)])
async def close(identifier: UUID):
    item = desktops.get(str(identifier))
    if item:
        await item.stop()
    return {"status": "closed"}
