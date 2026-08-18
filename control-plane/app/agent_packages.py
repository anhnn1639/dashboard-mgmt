from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes


PACKAGE_LABEL_RE = re.compile(r"[^A-Za-z0-9._-]+")
WINDOWS_MSI_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
LINUX_AGENT_PATH = Path("linux/x86_64/tram-agent")
LINUX_ELF_MAGIC = b"\x7fELF"


def certificate_sha256(pem: str) -> str:
    certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
    return certificate.fingerprint(hashes.SHA256()).hex()


def safe_package_label(value: str) -> str:
    normalized = PACKAGE_LABEL_RE.sub("-", value.strip()).strip("-._")
    return (normalized or "server")[:48]


def dashboard_netloc(dashboard_url: str) -> str:
    parsed = urlsplit(dashboard_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Dashboard URL must be an origin-only HTTPS URL before generating an agent")
    return parsed.netloc


def windows_msi_filename(dashboard_url: str, package_id: str, package_secret: str, ca_fingerprint: str) -> str:
    netloc = dashboard_netloc(dashboard_url)
    encoded_netloc = base64.urlsafe_b64encode(netloc.encode("utf-8")).decode("ascii").rstrip("=")
    filename = f"TramAgent--{encoded_netloc}--{package_id}--{package_secret}--{ca_fingerprint}.msi"
    if len(filename) > 240:
        raise ValueError("Dashboard hostname is too long for a safe Windows installer filename")
    return filename


def validate_windows_msi(path: Path) -> bytes:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise FileNotFoundError("The generic Windows MSI artifact is not available") from exc
    if len(content) < 4096 or not content.startswith(WINDOWS_MSI_MAGIC):
        raise ValueError("The generic Windows MSI artifact is invalid")
    return content


def validate_linux_agent(path: Path) -> bytes:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise FileNotFoundError("The standalone Linux x86_64 agent is not available") from exc
    if (
        len(content) < 1024 * 1024
        or not content.startswith(LINUX_ELF_MAGIC)
        or content[4:6] != b"\x02\x01"
        or content[18:20] != b"\x3e\x00"
    ):
        raise ValueError("The standalone Linux x86_64 agent artifact is invalid")
    return content


def _tar_entry(archive: tarfile.TarFile, name: str, content: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    archive.addfile(info, io.BytesIO(content))


def linux_run_bundle(
    assets_root: Path,
    *,
    dashboard_url: str,
    package_id: str,
    package_secret: str,
    ca_certificate: str,
    ca_fingerprint: str,
) -> bytes:
    dashboard_netloc(dashboard_url)
    required = {
        "VERSION": 0o640,
        str(LINUX_AGENT_PATH).replace("\\", "/"): 0o750,
        "tram-agent.service": 0o640,
        "install-linux.sh": 0o750,
    }
    root = assets_root.resolve()
    validate_linux_agent(root / LINUX_AGENT_PATH)
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, mode in required.items():
            source = (assets_root / name).resolve()
            try:
                source.relative_to(root)
            except ValueError as exc:
                raise FileNotFoundError(f"Agent asset is outside the asset root: {name}") from exc
            if not source.is_file():
                raise FileNotFoundError(f"Agent asset is missing: {name}")
            _tar_entry(archive, name, source.read_bytes(), mode)
        bootstrap = json.dumps(
            {
                "version": 1,
                "server_url": dashboard_url,
                "package_id": package_id,
                "package_secret": package_secret,
                "server_ca_certificate": ca_certificate,
                "server_ca_sha256": ca_fingerprint,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        _tar_entry(archive, "bootstrap.json", bootstrap, 0o600)

    launcher = b"""#!/bin/sh
set -eu
umask 077
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tram-agent.XXXXXX")
cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT HUP INT TERM
archive_line=$(awk '/^__TRAM_AGENT_ARCHIVE__$/ { print NR + 1; exit }' "$0")
if [ -z "$archive_line" ]; then
  echo "Invalid Tram Agent installer" >&2
  exit 2
fi
tail -n +"$archive_line" "$0" | tar -xzf - -C "$work_dir"
sh "$work_dir/install-linux.sh" "$work_dir/bootstrap.json"
exit 0
__TRAM_AGENT_ARCHIVE__
"""
    return launcher + payload.getvalue()
