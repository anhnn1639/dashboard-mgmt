from __future__ import annotations

import base64
import hashlib
import os
import re
import socket
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,179}$")
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


class ScannerUnavailable(RuntimeError):
    pass


@dataclass
class MalwareDetected(RuntimeError):
    signature: str

    def __str__(self) -> str:
        return f"Malware detected: {self.signature}"


def normalize_upload_name(filename: str | None) -> str:
    value = (filename or "").strip()
    if not SAFE_FILENAME.fullmatch(value) or value.endswith((".", " ")):
        raise ValueError("Filename must use safe ASCII letters, numbers, spaces, dot, dash or underscore")
    stem = value.split(".", 1)[0].upper()
    if stem in WINDOWS_RESERVED_NAMES or value in {".", ".."}:
        raise ValueError("Reserved filename")
    return value


def scan_with_clamav(data: bytes, host: str, port: int, timeout_seconds: int = 30) -> str:
    """Scan bytes using clamd INSTREAM. The clamd TCP socket must stay private."""
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as connection:
            connection.settimeout(timeout_seconds)
            connection.sendall(b"zINSTREAM\0")
            for offset in range(0, len(data), 64 * 1024):
                chunk = data[offset : offset + 64 * 1024]
                connection.sendall(struct.pack(">I", len(chunk)))
                connection.sendall(chunk)
            connection.sendall(struct.pack(">I", 0))
            reply = bytearray()
            while len(reply) < 16 * 1024:
                part = connection.recv(4096)
                if not part:
                    break
                reply.extend(part)
                if b"\0" in part:
                    break
    except (OSError, TimeoutError) as exc:
        raise ScannerUnavailable("Malware scanner is unavailable") from exc

    result = bytes(reply).split(b"\0", 1)[0].decode("utf-8", "replace").strip()
    if result.endswith(" OK"):
        return result
    if result.endswith(" FOUND"):
        signature = result.rsplit(":", 1)[-1].removesuffix(" FOUND").strip() or "unknown"
        raise MalwareDetected(signature)
    raise ScannerUnavailable(f"Malware scanner returned an invalid result: {result[:200]}")


def file_key(encoded_fernet_key: str) -> bytes:
    try:
        key = base64.urlsafe_b64decode(encoded_fernet_key.encode())
    except (ValueError, TypeError) as exc:
        raise ValueError("File encryption key is invalid") from exc
    if len(key) != 32:
        raise ValueError("File encryption key must contain 32 bytes")
    return hashlib.sha256(b"tram-ops-file-v1\0" + key).digest()


def file_aad(transfer_id: str, server_id: str, sha256: str) -> bytes:
    return f"tram-ops-file-v1\n{transfer_id}\n{server_id}\n{sha256}".encode()


def encrypt_file(data: bytes, transfer_id: str, server_id: str, sha256: str, encoded_key: str) -> tuple[bytes, str]:
    nonce = os.urandom(12)
    encrypted = AESGCM(file_key(encoded_key)).encrypt(nonce, data, file_aad(transfer_id, server_id, sha256))
    return encrypted, base64.b64encode(nonce).decode()


def decrypt_file(encrypted: bytes, nonce_b64: str, transfer_id: str, server_id: str, sha256: str, encoded_key: str) -> bytes:
    nonce = base64.b64decode(nonce_b64.encode(), validate=True)
    return AESGCM(file_key(encoded_key)).decrypt(nonce, encrypted, file_aad(transfer_id, server_id, sha256))
