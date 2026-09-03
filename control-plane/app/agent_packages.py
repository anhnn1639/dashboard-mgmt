from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import tarfile
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes


PACKAGE_LABEL_RE = re.compile(r"[^A-Za-z0-9._-]+")
WINDOWS_MSI_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
LINUX_AGENT_PATH = Path("linux/x86_64/tram-agent")
LINUX_ELF_MAGIC = b"\x7fELF"
LINUX_OFFLINE_PROFILES = (
    "ubuntu-22.04",
    "ubuntu-24.04",
    "ol-7",
    "ol-8",
)
LINUX_OFFLINE_ARCHIVE_MAX_BYTES = 95 * 1024 * 1024
LINUX_OFFLINE_EXPANDED_MAX_BYTES = 512 * 1024 * 1024
# Keep bundles reproducible without using the Unix epoch. GNU tar versions on
# Oracle Linux 7 warn that epoch-dated members are "implausibly old".
REPRODUCIBLE_ARCHIVE_MTIME = 1_704_067_200


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


def linux_offline_archive_path(assets_root: Path, profile: str) -> Path:
    if profile not in LINUX_OFFLINE_PROFILES:
        raise ValueError("Unsupported Linux offline dependency profile")
    return assets_root / "linux" / "offline" / f"{profile}-x86_64.tar"


def _validate_linux_offline_archive(content: bytes, profile: str) -> None:
    if not content or len(content) > LINUX_OFFLINE_ARCHIVE_MAX_BYTES:
        raise ValueError
    expected_suffix = ".deb" if profile.startswith("ubuntu-") else ".rpm"
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if not 2 <= len(members) <= 512 or len(names) != len(set(names)) or "manifest.json" not in names:
            raise ValueError
        expanded_size = 0
        for member in members:
            path = Path(member.name)
            if member.isdir():
                if member.name != "packages":
                    raise ValueError
                continue
            if not member.isfile() or path.is_absolute() or ".." in path.parts:
                raise ValueError
            is_ubuntu_index = profile.startswith("ubuntu-") and member.name == "packages/Packages"
            if member.name != "manifest.json" and not is_ubuntu_index and (path.parent.as_posix() != "packages" or path.suffix != expected_suffix):
                raise ValueError
            expanded_size += member.size
            if expanded_size > LINUX_OFFLINE_EXPANDED_MAX_BYTES:
                raise ValueError
        expected_names = {name for name in names if name.startswith("packages/") and name.endswith(expected_suffix)}
        if profile.startswith("ubuntu-"):
            index_member = archive.extractfile("packages/Packages") if "packages/Packages" in names else None
            index_content = index_member.read().decode("utf-8") if index_member else ""
            indexed_names = {f"packages/{name}" for name in re.findall(r"(?m)^Filename: \./([^\s/]+\.deb)$", index_content)}
            if indexed_names != expected_names:
                raise ValueError
        manifest_member = archive.extractfile("manifest.json")
        manifest = json.loads(manifest_member.read()) if manifest_member else None
        package_entries = manifest.get("packages") if isinstance(manifest, dict) else None
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"schema", "profile", "architecture", "packageType", "packages"}
            or manifest.get("schema") != 1
            or manifest.get("profile") != profile
            or manifest.get("architecture") != "x86_64"
            or manifest.get("packageType") != expected_suffix[1:]
            or not isinstance(package_entries, list)
            or not package_entries
        ):
            raise ValueError
        seen: set[str] = set()
        for entry in package_entries:
            if not isinstance(entry, dict) or set(entry) != {"name", "sha256", "sizeBytes"}:
                raise ValueError
            name = str(entry.get("name", ""))
            member_name = f"packages/{name}"
            if member_name not in expected_names or name in seen or Path(name).name != name:
                raise ValueError
            member = archive.extractfile(member_name)
            package_content = member.read() if member else b""
            if len(package_content) != entry.get("sizeBytes") or hashlib.sha256(package_content).hexdigest() != entry.get("sha256"):
                raise ValueError
            seen.add(name)
        if {f"packages/{name}" for name in seen} != expected_names:
            raise ValueError

@lru_cache(maxsize=len(LINUX_OFFLINE_PROFILES))
def _cached_linux_offline_archive(
    path_text: str,
    profile: str,
    mtime_ns: int,
    size_bytes: int,
    provenance_mtime_ns: int,
    provenance_size_bytes: int,
    release_version: str,
) -> tuple[int, str]:
    path = Path(path_text)
    content = path.read_bytes()
    if len(content) != size_bytes:
        raise ValueError
    try:
        _validate_linux_offline_archive(content, profile)
        provenance = json.loads(path.with_name(path.name + ".provenance.json").read_text(encoding="utf-8"))
    except OSError as exc:
        raise FileNotFoundError(f"Linux offline dependency archive is not available for {profile}") from exc
    except (tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise ValueError(f"Linux offline dependency archive is invalid for {profile}") from exc
    if (
        not isinstance(provenance, dict)
        or set(provenance) != {"schema", "version", "artifactKind", "profile", "architecture", "sha256", "sizeBytes", "sourceCommit"}
        or provenance.get("schema") != 1
        or provenance.get("version") != release_version
        or provenance.get("artifactKind") != "linux_offline_dependencies"
        or provenance.get("profile") != profile
        or provenance.get("architecture") != "x86_64"
        or provenance.get("sha256") != hashlib.sha256(content).hexdigest()
        or provenance.get("sizeBytes") != len(content)
        or not re.fullmatch(r"[0-9a-f]{40}", str(provenance.get("sourceCommit", "")))
    ):
        raise ValueError(f"Linux offline dependency provenance does not match release {release_version} for {profile}")
    return len(content), hashlib.sha256(content).hexdigest()


def validate_linux_offline_archive(
    assets_root: Path,
    profile: str,
    release_version: str,
    *,
    load_content: bool = True,
) -> bytes:
    path = linux_offline_archive_path(assets_root, profile)
    provenance_path = path.with_name(path.name + ".provenance.json")
    try:
        stat = path.stat()
        provenance_stat = provenance_path.stat()
    except OSError as exc:
        raise FileNotFoundError(f"Linux offline dependency archive is not available for {profile}") from exc
    expected_size, expected_sha256 = _cached_linux_offline_archive(
        str(path.resolve()),
        profile,
        stat.st_mtime_ns,
        stat.st_size,
        provenance_stat.st_mtime_ns,
        provenance_stat.st_size,
        release_version,
    )
    if not load_content:
        return b""
    content = path.read_bytes()
    if len(content) != expected_size or hashlib.sha256(content).hexdigest() != expected_sha256:
        _cached_linux_offline_archive.cache_clear()
        raise ValueError(f"Linux offline dependency archive changed while being read for {profile}")
    return content


def _tar_entry(archive: tarfile.TarFile, name: str, content: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = mode
    info.mtime = REPRODUCIBLE_ARCHIVE_MTIME
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    archive.addfile(info, io.BytesIO(content))


def linux_run_bundle(
    assets_root: Path,
    *,
    agent_content: bytes | None = None,
    dashboard_url: str,
    package_id: str,
    package_secret: str,
    ca_certificate: str,
    ca_fingerprint: str,
    linux_profile: str,
) -> bytes:
    dashboard_netloc(dashboard_url)
    required = {
        "VERSION": 0o640,
        str(LINUX_AGENT_PATH).replace("\\", "/"): 0o750,
        "tram-agent.service": 0o640,
        "install-linux.sh": 0o750,
    }
    root = assets_root.resolve()
    release_version = (root / "VERSION").read_text(encoding="ascii").strip()
    offline_content = validate_linux_offline_archive(root, linux_profile, release_version)
    if agent_content is None:
        agent_content = validate_linux_agent(root / LINUX_AGENT_PATH)
    elif (
        len(agent_content) < 1024 * 1024
        or not agent_content.startswith(LINUX_ELF_MAGIC)
        or agent_content[4:6] != b"\x02\x01"
        or agent_content[18:20] != b"\x3e\x00"
    ):
        raise ValueError("The standalone Linux x86_64 agent artifact is invalid")
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, mode in required.items():
            if name == str(LINUX_AGENT_PATH).replace("\\", "/"):
                # The caller may supply the exact bytes already validated
                # against release provenance. Never reopen that executable
                # between validation and packaging.
                _tar_entry(archive, name, agent_content, mode)
                continue
            source = (assets_root / name).resolve()
            try:
                source.relative_to(root)
            except ValueError as exc:
                raise FileNotFoundError(f"Agent asset is outside the asset root: {name}") from exc
            if not source.is_file():
                raise FileNotFoundError(f"Agent asset is missing: {name}")
            _tar_entry(archive, name, source.read_bytes(), mode)
        offline_digest = hashlib.sha256(offline_content).hexdigest()
        _tar_entry(archive, "linux-profile", f"{linux_profile}\n".encode("ascii"), 0o640)
        _tar_entry(archive, "offline-dependencies.tar", offline_content, 0o640)
        _tar_entry(
            archive,
            "offline-dependencies.sha256",
            f"{offline_digest}  offline-dependencies.tar\n".encode("ascii"),
            0o640,
        )
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
tail -n +"$archive_line" "$0" | tar -xf - -C "$work_dir"
sh "$work_dir/install-linux.sh" "$work_dir/bootstrap.json"
exit 0
__TRAM_AGENT_ARCHIVE__
"""
    return launcher + payload.getvalue()
