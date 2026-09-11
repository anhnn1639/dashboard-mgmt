"""Check internal Guacamole authentication and SSH/RDP protocol availability.

The temporary JSON identity has no connections or vault credentials. Protocol
checks stop before sending connect, so no managed server is contacted. Never
print request URLs, responses, secrets, or authentication tokens.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


BASE_URL = "http://guacamole:8080/guacamole"


def probe_identity(key_hex):
    if not re.fullmatch(r"[0-9a-fA-F]{32}", key_hex):
        raise RuntimeError("Guacamole check: API JSON authentication key is missing or invalid")
    key = bytes.fromhex(key_hex)
    identity = {"username": "deployment-check-" + secrets.token_hex(8),
                "expires": int((time.time() + 30) * 1000), "connections": {}}
    body = json.dumps(identity, separators=(",", ":")).encode()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(hmac.new(key, body, hashlib.sha256).digest() + body) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    return base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode()


def verify_authentication_once(opener, key_hex):
    data = urlencode({"data": probe_identity(key_hex)}).encode()
    token = None
    try:
        request = Request(BASE_URL + "/api/tokens", data=data,
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
        with opener.open(request, timeout=5) as response:
            payload = json.loads(response.read(65537))
        if not isinstance(payload, dict):
            raise ValueError("Invalid response")
        token = payload.get("authToken")
        if not isinstance(token, str) or not token or len(token) > 4096:
            token = None
            raise ValueError("Missing authentication token")
        if payload.get("dataSource") != "json":
            raise ValueError("JSON authentication unavailable")
    except HTTPError as error:
        if error.code in {404, 502, 503, 504}:
            raise ConnectionError("Guacamole is starting") from None
        raise RuntimeError(f"Guacamole JSON authentication check returned HTTP {error.code}; check the JSON extension and API/Guacamole key agreement") from None
    except (URLError, TimeoutError, OSError):
        raise ConnectionError("Guacamole is starting") from None
    except ValueError:
        raise RuntimeError("Guacamole JSON authentication check failed; check service readiness and the internal API-to-Guacamole route") from None
    finally:
        if token:
            try:
                request = Request(BASE_URL + "/api/tokens/" + quote(token, safe=""), method="DELETE")
                with opener.open(request, timeout=5) as response:
                    response.read(1024)
            except HTTPError as error:
                if error.code != 404:
                    raise RuntimeError("Guacamole check could not release its temporary empty session") from None
            except Exception:
                raise RuntimeError("Guacamole check could not release its temporary empty session") from None
    print("Guacamole JSON authentication ready; temporary empty session released")


def verify_authentication(opener, key_hex, deadline_seconds=45):
    deadline = time.monotonic() + deadline_seconds
    while True:
        try:
            verify_authentication_once(opener, key_hex)
            return
        except ConnectionError:
            if time.monotonic() >= deadline:
                raise RuntimeError("Guacamole did not become ready; check Tomcat startup and the internal API-to-Guacamole route") from None
            time.sleep(min(1, max(0, deadline - time.monotonic())))


def verify_stylesheet(opener):
    try:
        with opener.open(BASE_URL + "/app.css", timeout=5) as response:
            mime = response.headers.get_content_type()
            body = response.read(1024 * 1024 + 1)
        if mime != "text/css" or not body or len(body) > 1024 * 1024:
            raise ValueError("Stylesheet unavailable")
    except (HTTPError, URLError, OSError, ValueError):
        raise RuntimeError("Guacamole extension CSS is empty or has the wrong MIME type; rebuild/recreate Guacamole with the current extension") from None
    print("Guacamole extension stylesheet ready with text/css MIME")


def read_instruction(connection, deadline_seconds=5):
    deadline = time.monotonic() + deadline_seconds

    def receive(size):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Guacamole handshake deadline expired")
        connection.settimeout(remaining)
        return connection.recv(size)

    result = []
    total = 0
    while len(result) < 512:
        digits = bytearray()
        while True:
            char = receive(1)
            if char == b".":
                break
            if not char or not char.isdigit() or len(digits) >= 6:
                raise ValueError("Invalid protocol length")
            digits.extend(char)
        if not digits:
            raise ValueError("Missing protocol length")
        size = int(digits)
        total += size
        if total > 65536:
            raise ValueError("Oversized protocol instruction")
        value = bytearray()
        while len(value) < size:
            chunk = receive(size - len(value))
            if not chunk:
                raise ValueError("Incomplete protocol instruction")
            value.extend(chunk)
        result.append(value.decode("utf-8"))
        separator = receive(1)
        if separator == b";":
            return result
        if separator != b",":
            raise ValueError("Invalid protocol separator")
    raise ValueError("Too many protocol arguments")


def verify_protocol(protocol, connect=socket.create_connection):
    if protocol not in {"ssh", "rdp"}:
        raise ValueError("Unsupported deployment protocol check")
    try:
        with connect(("guacd", 4822), timeout=5) as connection:
            connection.settimeout(5)
            connection.sendall(f"6.select,{len(protocol)}.{protocol};".encode())
            reply = read_instruction(connection)
            if not reply or reply[0] != "args" or not {"hostname", "port"}.issubset(reply[1:]):
                raise ValueError("Protocol unavailable")
            # Closing now deliberately prevents a remote connection/recording.
    except (OSError, ValueError):
        raise RuntimeError(f"Guacamole {protocol.upper()} handshake check failed; check API-to-guacd networking and protocol support") from None
    print(f"Guacamole {protocol.upper()} protocol ready; no remote target contacted")


if __name__ == "__main__":
    try:
        opener = build_opener(ProxyHandler({}))
        verify_authentication(opener, os.environ.get("GUACAMOLE_JSON_SECRET", ""))
        verify_stylesheet(opener)
        for protocol in ("ssh", "rdp"):
            verify_protocol(protocol)
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
