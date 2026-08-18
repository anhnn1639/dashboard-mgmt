from __future__ import annotations

import argparse
import base64
import contextlib
from concurrent.futures import Future, ThreadPoolExecutor
import getpass
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import os
import platform
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import psutil
import requests
import websocket
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def load_agent_version() -> str:
    runtime_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    try:
        version = (runtime_root / "VERSION").read_text(encoding="ascii").strip()
    except OSError as exc:
        raise RuntimeError("Agent VERSION file is missing") from exc
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise RuntimeError("Agent VERSION is invalid")
    return version


AGENT_VERSION = load_agent_version()
LOG = logging.getLogger("tram-agent")
NAME_RE = re.compile(r"^[A-Za-z0-9_.@\\-]{1,128}$")
GROUP_RE = re.compile(r"^[A-Za-z0-9_.@ -]{1,128}$")
LINUX_ACCOUNT_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
WINDOWS_ACCOUNT_RE = re.compile(r"^[^\\/\[\]:;|=,+*?<>@\x00-\x1f]{1,20}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,160}$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.:@~-]{0,254}$")
DEVICE_RE = re.compile(r"^/dev/[A-Za-z0-9_.+/-]{1,180}$")
MOUNT_PATH_RE = re.compile(r"^/(?:[A-Za-z0-9_.-]+/?){1,12}$")
FIREWALL_OBJECT_RE = re.compile(r"^[A-Za-z0-9_.@:+/-]{1,160}$")
TRANSFER_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,179}$")
SYSTEM_COMMAND_DIRS = tuple(Path(value) for value in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"))
WINDOWS_RESERVED_FILENAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
MAX_TRANSFER_BYTES = 50 * 1024 * 1024
MAX_CONCURRENT_TUNNELS = 4
WINDOWS_UPDATE_SCAN_TIMEOUT_SECONDS = 240
WINDOWS_UPDATE_METRIC_TIMEOUT_SECONDS = 30
ACTIVE_TUNNELS: set[str] = set()
ACTIVE_TUNNELS_LOCK = threading.Lock()
ALLOWED_ACTIONS = {
    "inventory.collect", "service.list", "service.restart", "service.start", "service.stop",
    "user.create", "user.update", "user.disable", "user.enable", "user.delete", "user.password.reset",
    "group.create", "group.delete", "user.add_group", "patch.scan",
    "patch.install", "logs.sources", "logs.read", "process.list", "process.kill", "firewall.list", "system.reboot",
    "user.list", "group.list", "group.remove_user", "storage.list", "storage.extend", "storage.shrink",
    "storage.create", "storage.delete",
    "firewall.rule.add", "firewall.rule.add.auto", "firewall.rule.remove", "firewall.rule.reorder", "network.list", "file.deliver",
}


def find_system_command(name: str) -> str | None:
    resolved = shutil.which(name)
    if resolved:
        return resolved
    for directory in SYSTEM_COMMAND_DIRS:
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def configure_logging(log_file: str | None = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)


class Config:
    def __init__(self, path: str):
        self.path = Path(path)
        raw = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
        self.server_url = str(raw.get("server_url", "")).rstrip("/")
        self.agent_endpoint = str(raw.get("agent_endpoint", "")).rstrip("/")
        self.agent_id = str(raw.get("agent_id", "")) or str(uuid.uuid4())
        self.cert_file = Path(raw.get("cert_file", self.path.parent / "agent.crt"))
        self.key_file = Path(raw.get("key_file", self.path.parent / "agent.key"))
        self.ca_file = Path(raw.get("ca_file", self.path.parent / "agent-ca.crt"))
        self.server_ca_file = Path(raw["server_ca_file"]) if raw.get("server_ca_file") else None
        self.interval = max(15, int(raw.get("interval", 30)))
        self.inventory_interval = max(300, int(raw.get("inventory_interval", 1800)))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"server_url": self.server_url, "agent_endpoint": self.agent_endpoint, "agent_id": self.agent_id, "cert_file": str(self.cert_file), "key_file": str(self.key_file), "ca_file": str(self.ca_file), "server_ca_file": str(self.server_ca_file) if self.server_ca_file else "", "interval": self.interval, "inventory_interval": self.inventory_interval}, indent=2), encoding="utf-8")

    def tls_verify(self) -> bool | str:
        return str(self.server_ca_file) if self.server_ca_file else True


def signed_headers(config: Config, method: str, url: str, body: bytes = b"") -> dict[str, str]:
    timestamp = str(int(time.time()))
    path = urlsplit(url).path
    message = f"{timestamp}\n{method.upper()}\n{path}\n{hashlib.sha256(body).hexdigest()}".encode()
    certificate = x509.load_pem_x509_certificate(config.cert_file.read_bytes())
    private_key = serialization.load_pem_private_key(config.key_file.read_bytes(), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise RuntimeError("Agent private key must be an EC key")
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return {
        "X-Tram-Agent-Certificate": base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode(),
        "X-Tram-Agent-Timestamp": timestamp,
        "X-Tram-Agent-Signature": base64.b64encode(signature).decode(),
    }


def signed_request(config: Config, method: str, url: str, payload: dict[str, Any]) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return body, {"Content-Type": "application/json", **signed_headers(config, method, url, body)}


def run(command: list[str], timeout: int = 120, check: bool = False, sensitive: bool = False, output_limit: int = 100_000) -> tuple[int, str]:
    if not sensitive:
        LOG.info("exec action: %s", command[0])
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        detail = "\n".join(part.strip() for part in (stdout, stderr) if part and part.strip())
        message = f"Command timed out after {timeout} seconds"
        return 124, (f"{message}\n{detail}" if detail else message)[-output_limit:]
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    output = stdout if completed.returncode == 0 else "\n".join(part for part in (stdout, stderr) if part)
    if check and completed.returncode:
        raise RuntimeError(output or f"Command failed: {completed.returncode}")
    return completed.returncode, output[-output_limit:]


def run_with_input(command: list[str], input_value: str, timeout: int = 120) -> tuple[int, str]:
    completed = subprocess.run(command, input=input_value, text=True, capture_output=True, timeout=timeout, check=False, encoding="utf-8", errors="replace")
    output = completed.stdout.strip() if completed.returncode == 0 else "\n".join(part for part in (completed.stdout.strip(), completed.stderr.strip()) if part)
    return completed.returncode, output[-100_000:]


def powershell(script: str, timeout: int = 120, output_limit: int = 100_000) -> tuple[int, str]:
    encoded = base64.b64encode(script.encode("utf-16le")).decode()
    return run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded], timeout=timeout, sensitive=True, output_limit=output_limit)


def parse_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    path = Path("/etc/os-release")
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    return values


def network_addresses() -> list[str]:
    result: list[str] = []

    def add(value: str) -> None:
        normalized = value.split("%")[0].strip()
        if normalized and normalized not in result:
            result.append(normalized)

    try:
        for addresses in psutil.net_if_addrs().values():
            for address in addresses:
                if address.family in {socket.AF_INET, socket.AF_INET6}:
                    add(address.address)
    except OSError as exc:
        LOG.warning("psutil cannot enumerate network interfaces: %s", exc)

    if not result and platform.system().lower() == "linux":
        ip_tool = next((path for path in ("/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip") if Path(path).exists()), "")
        if ip_tool:
            code, output = run([ip_tool, "-json", "address", "show"])
            if code == 0:
                try:
                    for interface in json.loads(output):
                        for address in interface.get("addr_info", []):
                            if address.get("family") in {"inet", "inet6"}:
                                add(str(address.get("local", "")))
                except (TypeError, ValueError):
                    LOG.warning("ip command returned invalid JSON")

    if not result:
        hostname = socket.gethostname()
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                for info in socket.getaddrinfo(hostname, None, family=family, type=socket.SOCK_STREAM):
                    add(str(info[4][0]))
            except OSError:
                continue
    return result


def first_ssh_host_key(candidates: list[Path]) -> str | None:
    """Return the first usable OpenSSH public host key from candidates."""
    for candidate in candidates:
        if candidate.exists():
            parts = candidate.read_text(errors="replace").strip().split()
            if len(parts) >= 2:
                return f"{parts[0]} {parts[1]}"
    return None


def ssh_host_key() -> str | None:
    # guacd 1.6.0 uses libssh2, whose default host-key preference is ECDSA
    # P-256 before Ed25519 and RSA. Guacamole verifies the key negotiated by
    # libssh2 after the handshake, so the inventory key must follow that same
    # order instead of always pinning Ed25519.
    if platform.system().lower() == "windows":
        ssh_root = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "ssh"
    else:
        ssh_root = Path("/etc/ssh")
    return first_ssh_host_key([
        ssh_root / "ssh_host_ecdsa_key.pub",
        ssh_root / "ssh_host_ed25519_key.pub",
        ssh_root / "ssh_host_rsa_key.pub",
    ])


def rdp_certificate_fingerprint() -> str | None:
    if platform.system().lower() != "windows":
        return None
    code, output = powershell("$s=Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter \"TerminalName='RDP-tcp'\" -ErrorAction Stop;$s.SSLCertificateSHA1Hash")
    fingerprint = re.sub(r"[^0-9A-Fa-f]", "", output)
    return f"sha1:{fingerprint.lower()}" if code == 0 and len(fingerprint) == 40 else None


def management_facts(os_family: str) -> dict[str, Any]:
    if os_family == "windows":
        code, output = powershell("[pscustomobject]@{Users=@(Get-LocalUser|Select Name,Enabled,LastLogon);Groups=@(Get-LocalGroup|ForEach-Object{$g=$_;[pscustomobject]@{name=$g.Name;members=@(Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue|ForEach-Object Name)}});Storage=@(Get-Volume|Where-Object DriveLetter|Select DriveLetter,FileSystemLabel,FileSystem,Size,SizeRemaining);Services=@(Get-Service|Select Name,DisplayName,Status,StartType)}|ConvertTo-Json -Depth 5 -Compress")
        if code == 0:
            try:
                return json.loads(output)
            except ValueError:
                pass
        return {"Users": [], "Groups": [], "Storage": []}
    import grp
    import pwd
    users = [{"name": item.pw_name, "uid": item.pw_uid, "home": item.pw_dir, "shell": item.pw_shell} for item in pwd.getpwall() if item.pw_uid == 0 or item.pw_uid >= 1000]
    groups = [{"name": item.gr_name, "gid": item.gr_gid, "members": item.gr_mem} for item in grp.getgrall()]
    lsblk = find_system_command("lsblk")
    code, output = run([lsblk, "--json", "--bytes", "--output", "NAME,PATH,TYPE,FSTYPE,SIZE,MOUNTPOINTS"]) if lsblk else (127, "")
    try:
        storage = json.loads(output).get("blockdevices", []) if code == 0 else []
    except ValueError:
        storage = []
    logical_volumes: list[dict[str, Any]] = []
    lvs = find_system_command("lvs")
    if lvs:
        lvs_code, lvs_output = run([lvs, "--reportformat", "json", "--units", "b", "--nosuffix", "--options", "lv_path,vg_name,lv_name,lv_size,data_percent"])
        if lvs_code == 0:
            try:
                logical_volumes = json.loads(lvs_output).get("report", [{}])[0].get("lv", [])
            except (ValueError, IndexError):
                pass
    systemctl = find_system_command("systemctl")
    services_code, services_output = run([systemctl, "list-unit-files", "--type=service", "--no-legend", "--no-pager"]) if systemctl else (127, "")
    services = [{"name": line.split()[0], "state": line.split()[1] if len(line.split()) > 1 else ""} for line in services_output.splitlines() if services_code == 0 and line.strip()]
    return {"Users": users, "Groups": groups, "Storage": storage, "LogicalVolumes": logical_volumes, "Services": services}


def collect_inventory() -> dict[str, Any]:
    system = platform.system().lower()
    if system == "windows":
        code, output = powershell("$o=Get-CimInstance Win32_OperatingSystem; [pscustomobject]@{Caption=$o.Caption;Version=$o.Version;Build=$o.BuildNumber;ProductType=$o.ProductType}|ConvertTo-Json -Compress")
        details = json.loads(output) if code == 0 and output.startswith("{") else {}
        os_name = details.get("Caption") or platform.platform()
        os_version = f"{details.get('Version','')} build {details.get('Build','')}".strip()
        distribution_id = "windows"
    elif system == "linux":
        release = parse_os_release()
        os_name = release.get("PRETTY_NAME") or platform.platform()
        os_version = release.get("VERSION_ID") or platform.release()
        distribution_id = release.get("ID", "linux").lower()
    else:
        raise RuntimeError(f"Unsupported operating system: {system}")
    boot_id = ""
    boot_path = Path("/proc/sys/kernel/random/boot_id")
    if boot_path.exists():
        boot_id = boot_path.read_text().strip()
    os_family = "windows" if system == "windows" else "linux"
    extra = {"kernel": platform.release(), "python": platform.python_version(), **management_facts(os_family)}
    if os_family == "windows":
        extra["rdp_certificate_fingerprint"] = rdp_certificate_fingerprint()
    return {"hostname": socket.gethostname(), "os_family": os_family, "os_name": os_name, "os_version": os_version, "distribution_id": distribution_id, "architecture": platform.machine(), "agent_version": AGENT_VERSION, "addresses": network_addresses(), "boot_id": boot_id, "ssh_host_key": ssh_host_key(), "extra": extra}


def pending_updates(inventory: dict[str, Any]) -> int:
    if inventory["os_family"] == "windows":
        # The heartbeat metric must never start a network WUA scan. The full
        # patch.scan job below owns the online search and its longer timeout.
        script = "$s=New-Object -ComObject Microsoft.Update.Session;$q=$s.CreateUpdateSearcher();$q.Online=$false;$r=$q.Search(\"IsInstalled=0 and IsHidden=0\");$r.Updates.Count"
        code, output = powershell(script, timeout=WINDOWS_UPDATE_METRIC_TIMEOUT_SECONDS)
    elif inventory["distribution_id"] == "ubuntu":
        code, output = run(["/usr/bin/apt-get", "-s", "upgrade"], timeout=180)
        return sum(1 for line in output.splitlines() if line.startswith("Inst ")) if code == 0 else 0
    else:
        package_tool = "/usr/bin/dnf" if Path("/usr/bin/dnf").exists() else "/usr/bin/yum"
        code, output = run([package_tool, "-q", "check-update"], timeout=180)
        return sum(1 for line in output.splitlines() if re.match(r"^[A-Za-z0-9_.+:-]+\s+\S+\s+\S+", line)) if code in {0, 100} else 0
    try:
        return int(output.strip().splitlines()[-1]) if code == 0 else 0
    except (ValueError, IndexError):
        return 0


def services_running(os_family: str) -> int:
    if os_family == "windows":
        code, output = powershell("@(Get-Service|Where-Object Status -eq 'Running').Count")
    else:
        code, output = run(["/usr/bin/systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"])
        return len([line for line in output.splitlines() if line.strip()]) if code == 0 else 0
    try:
        return int(output.strip().splitlines()[-1]) if code == 0 else 0
    except (ValueError, IndexError):
        return 0


def collect_metrics(inventory: dict[str, Any], include_expensive: bool) -> dict[str, Any]:
    disk = max((usage.percent for part in psutil.disk_partitions(all=False) if (usage := safe_disk_usage(part.mountpoint)) is not None), default=0)
    memory = psutil.virtual_memory().percent
    return {"cpu_percent": psutil.cpu_percent(interval=1), "memory_percent": memory, "disk_percent": disk, "uptime_seconds": max(0, int(time.time() - psutil.boot_time())), "pending_updates": pending_updates(inventory) if include_expensive else None, "services_running": services_running(inventory["os_family"]) if include_expensive else None, "alerts": int(disk >= 90) + int(memory >= 90)}


def safe_disk_usage(path: str):
    try:
        return psutil.disk_usage(path)
    except (PermissionError, OSError):
        return None


def require_name(parameters: dict[str, Any], key: str, service: bool = False) -> str:
    value = str(parameters.get(key, ""))
    matcher = SERVICE_RE if service else NAME_RE
    if not matcher.fullmatch(value):
        raise ValueError(f"Invalid {key}")
    return value


def require_group(parameters: dict[str, Any]) -> str:
    value = str(parameters.get("group", ""))
    if not GROUP_RE.fullmatch(value):
        raise ValueError("Invalid group")
    return value


def firewall_address(value: Any) -> str:
    normalized = str(value or "any").strip().lower()
    return "any" if normalized in {"", "any"} else str(ipaddress.ip_network(normalized, strict=False))


def firewall_parameters(parameters: dict[str, Any]) -> dict[str, Any]:
    name = str(parameters.get("name", "")).strip()
    if not 1 <= len(name) <= 128 or any(ord(character) < 32 for character in name):
        raise ValueError("Invalid firewall rule name")
    local_port_value = parameters.get("local_port", parameters.get("port", 0))
    local_port = "any" if str(local_port_value).strip().lower() == "any" else int(local_port_value)
    remote_port_value = parameters.get("remote_port", "any")
    remote_port = "any" if str(remote_port_value).strip().lower() in {"", "any"} else int(remote_port_value)
    protocol = str(parameters.get("protocol", "tcp")).lower()
    rule_action = str(parameters.get("action", "allow")).lower()
    direction = str(parameters.get("direction", "in")).lower()
    if (local_port != "any" and not 1 <= local_port <= 65535) or (remote_port != "any" and not 1 <= remote_port <= 65535):
        raise ValueError("Invalid firewall port")
    if protocol not in {"tcp", "udp"} or rule_action not in {"allow", "deny", "reject"} or direction not in {"in", "out"}:
        raise ValueError("Invalid firewall rule")
    return {
        "name": name,
        "local_port": local_port,
        "remote_port": remote_port,
        "protocol": protocol,
        "action": rule_action,
        "direction": direction,
        "source": firewall_address(parameters.get("source", "any")),
        "destination": firewall_address(parameters.get("destination", "any")),
    }


def ufw_endpoint(value: str, family: str) -> tuple[str, str, str, str] | None:
    normalized = re.sub(r"\s+\(v6\)\s*$", "", value.strip(), flags=re.IGNORECASE)
    interface = ""
    interface_match = re.match(r"^(.*?)\s+on\s+([A-Za-z0-9_.:@+-]+)$", normalized)
    if interface_match:
        normalized, interface = interface_match.groups()
    port = ""
    protocol = ""
    port_match = re.search(r"(?:^|\s)(\d{1,5}(?:-\d{1,5})?)/(tcp|udp)$", normalized, re.IGNORECASE)
    if port_match:
        port, protocol = port_match.groups()
        normalized = normalized[:port_match.start()].strip()
        for part in port.split("-"):
            if not 1 <= int(part) <= 65535:
                return None
    if normalized.lower() == "anywhere" or not normalized:
        address = "::/0" if family == "ipv6" else "0.0.0.0/0"
    else:
        try:
            network = ipaddress.ip_network(normalized, strict=False)
        except ValueError:
            return None
        if network.version != (6 if family == "ipv6" else 4):
            return None
        address = str(network)
    return address, port, protocol.lower(), interface


def ufw_insert_arguments(destination: str, action: str, direction: str, source: str, comment: str, family: str) -> list[str] | None:
    destination_endpoint = ufw_endpoint(destination, family)
    source_endpoint = ufw_endpoint(source, family)
    if not destination_endpoint or not source_endpoint:
        return None
    destination_address, destination_port, destination_protocol, destination_interface = destination_endpoint
    source_address, source_port, source_protocol, source_interface = source_endpoint
    if source_port or (source_protocol and destination_protocol and source_protocol != destination_protocol):
        return None
    protocol = destination_protocol or source_protocol
    command = [action.lower()]
    normalized_direction = (direction or "IN").upper()
    if normalized_direction == "FWD":
        command.insert(0, "route")
        if source_interface:
            command += ["in", "on", source_interface]
        if destination_interface:
            command += ["out", "on", destination_interface]
    elif normalized_direction == "OUT":
        command += ["out"]
        if source_interface:
            command += ["on", source_interface]
        if destination_interface:
            return None
    elif normalized_direction == "IN":
        command += ["in"]
        if destination_interface:
            command += ["on", destination_interface]
        if source_interface:
            return None
    else:
        return None
    if protocol:
        command += ["proto", protocol]
    command += ["from", source_address, "to", destination_address]
    if destination_port:
        command += ["port", destination_port]
    if comment:
        if len(comment) > 255 or any(ord(character) < 32 for character in comment):
            return None
        command += ["comment", comment]
    return command


def parse_ufw_rules(output: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s{2,}(.+?)\s*$", line, re.IGNORECASE)
        if not match:
            continue
        number, destination, action, direction, source = match.groups()
        comment = ""
        if " # " in source:
            source, comment = source.split(" # ", 1)
        family = "ipv6" if "(v6)" in destination.lower() or "(v6)" in source.lower() else "ipv4"
        insert_arguments = ufw_insert_arguments(destination, action, direction or "IN", source, comment, family)
        port_match = re.search(r"\b(\d{1,5})(?:/(tcp|udp))?\b", destination, re.IGNORECASE)
        rules.append({
            "id": number,
            "backend": "ufw",
            "name": f"UFW #{number}",
            "direction": (direction or "IN").lower(),
            "action": action.lower(),
            "enabled": True,
            "protocol": (port_match.group(2) if port_match and port_match.group(2) else "any").lower(),
            "localPort": port_match.group(1) if port_match else destination,
            "remotePort": "any",
            "source": source,
            "destination": destination,
            "profile": "active",
            "raw": line.strip(),
            "removable": True,
            "reorderable": insert_arguments is not None,
            "orderGroup": f"ufw:{family}",
            "spec": {"number": int(number), "family": family, "insertArguments": insert_arguments or []},
        })
    return rules


def parse_firewalld_rules(output: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    zone = ""
    field = ""
    counters: dict[tuple[str, str], int] = {}
    supported = {"services", "ports", "protocols", "source-ports", "forward-ports", "icmp-blocks", "rich rules"}
    for raw_line in output.splitlines():
        if raw_line and not raw_line.startswith((" ", "\t")):
            zone = raw_line.split()[0]
            field = ""
            continue
        stripped = raw_line.strip()
        if not zone or not stripped:
            continue
        if field in {"rich rules", "forward-ports"} and (stripped.startswith("rule ") or stripped.startswith("port=")):
            values = [stripped]
        elif ":" in stripped:
            candidate, value = stripped.split(":", 1)
            candidate = candidate.strip()
            if candidate in supported:
                field = candidate
                values = [value.strip()] if candidate in {"rich rules", "forward-ports"} and value.strip() else value.split()
            else:
                field = ""
                continue
        elif field in {"rich rules", "forward-ports"}:
            values = [stripped]
        else:
            continue
        for value in values:
            if not value:
                continue
            key = (zone, field)
            counters[key] = counters.get(key, 0) + 1
            action_match = re.search(r"\b(accept|drop|reject)\b", value)
            protocol_match = re.search(r'(?:protocol=\"?|/)(tcp|udp)\b', value, re.IGNORECASE)
            port_match = re.search(r'(?:port port=\"?|^)(\d+(?:-\d+)?)', value)
            source_match = re.search(r'source address=\"([^\"]+)\"', value)
            rules.append({
                "id": f"{zone}:{field}:{counters[key]}",
                "backend": "firewalld",
                "name": f"{zone} · {field.rstrip('s')} · {value}",
                "direction": "in",
                "action": (action_match.group(1) if action_match else "allow").lower(),
                "enabled": True,
                "protocol": (protocol_match.group(1) if protocol_match else "any").lower(),
                "localPort": port_match.group(1) if port_match else (f"service:{value}" if field == "services" else "any"),
                "remotePort": "any",
                "source": source_match.group(1) if source_match else "any",
                "destination": "any",
                "profile": zone,
                "raw": value,
                "removable": True,
                "reorderable": False,
                "spec": {"zone": zone, "type": field, "value": value},
            })
    return rules


def parse_firewalld_zones(output: str) -> list[str]:
    return sorted({
        line.split()[0]
        for line in output.splitlines()
        if line and not line.startswith((" ", "\t")) and FIREWALL_OBJECT_RE.fullmatch(line.split()[0])
    })


def parse_nft_rules(output: str) -> list[dict[str, Any]]:
    try:
        documents = json.loads(output).get("nftables", [])
    except (AttributeError, ValueError):
        return []
    rules: list[dict[str, Any]] = []
    for document in documents:
        rule = document.get("rule") if isinstance(document, dict) else None
        if not isinstance(rule, dict) or not isinstance(rule.get("handle"), int):
            continue
        expression = rule.get("expr", [])
        raw = json.dumps(expression, ensure_ascii=False, separators=(",", ":"))
        verdict = next((name for name in ("accept", "drop", "reject") if f'"{name}"' in raw), "unknown")
        family, table, chain, handle = (str(rule.get(key, "")) for key in ("family", "table", "chain", "handle"))
        rules.append({
            "id": f"{family}:{table}:{chain}:{handle}",
            "backend": "nftables",
            "name": str(rule.get("comment") or f"{table}/{chain} #{handle}"),
            "direction": chain.lower() if chain.lower() in {"input", "output", "forward"} else "chain",
            "action": verdict,
            "enabled": True,
            "protocol": "any",
            "localPort": "expression",
            "remotePort": "any",
            "source": "see expression",
            "destination": "see expression",
            "profile": family,
            "raw": raw,
            "removable": True,
            "reorderable": True,
            "orderGroup": f"nftables:{family}:{table}:{chain}",
            "spec": {"family": family, "table": table, "chain": chain, "handle": int(handle), "comment": str(rule.get("comment") or "")},
        })
    return rules


def parse_nft_filter_targets(output: str) -> list[dict[str, str]]:
    try:
        documents = json.loads(output).get("nftables", [])
    except (AttributeError, ValueError):
        return []
    targets: list[dict[str, str]] = []
    for document in documents:
        chain = document.get("chain") if isinstance(document, dict) else None
        if not isinstance(chain, dict) or chain.get("type") != "filter":
            continue
        hook = str(chain.get("hook", "")).lower()
        if hook not in {"input", "output"}:
            continue
        family, table, name = (str(chain.get(key, "")) for key in ("family", "table", "name"))
        if family not in {"ip", "ip6", "inet"} or not FIREWALL_OBJECT_RE.fullmatch(table) or not FIREWALL_OBJECT_RE.fullmatch(name):
            continue
        direction = "in" if hook == "input" else "out"
        targets.append({
            "id": f"{family}:{table}:{name}",
            "label": f"{family} {table} → {name} ({hook.upper()})",
            "family": family,
            "table": table,
            "chain": name,
            "direction": direction,
        })
    return targets


IPTABLES_TABLES = ("filter", "nat", "mangle", "raw", "security")


def parse_iptables_rules(output: str, family: str) -> list[dict[str, Any]]:
    table = "filter"
    indexes: dict[tuple[str, str], int] = {}
    rules: list[dict[str, Any]] = []
    for line in output.splitlines():
        if line.startswith("*"):
            table = line[1:].strip()
            continue
        if not line.startswith("-A "):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue
        chain = tokens[1]
        key = (table, chain)
        indexes[key] = indexes.get(key, 0) + 1
        def option(name: str, fallback: str = "any") -> str:
            try:
                return tokens[tokens.index(name) + 1]
            except (ValueError, IndexError):
                return fallback
        index = indexes[key]
        target = option("-j", "unknown")
        comment = option("--comment", "")
        docker_managed = (chain.upper().startswith("DOCKER") and chain.upper() != "DOCKER-USER") or target.upper().startswith("DOCKER")
        rules.append({
            "id": f"{family}:{table}:{chain}:{index}",
            "backend": "iptables",
            "name": comment or f"{family} {table}/{chain} #{index}",
            "direction": chain.lower(),
            "action": target.lower(),
            "enabled": True,
            "protocol": option("-p"),
            "localPort": option("--dport"),
            "remotePort": option("--sport"),
            "source": option("-s"),
            "destination": option("-d"),
            "profile": family,
            "raw": line,
            "removable": not docker_managed,
            "reorderable": not docker_managed,
            "managedBy": "docker" if docker_managed else "",
            "orderGroup": f"iptables:{family}:{table}:{chain}",
            "spec": {"family": family, "table": table, "chain": chain, "index": index},
        })
    return rules


def parse_iptables_filter_targets(output: str, family: str) -> list[dict[str, str]]:
    table = "filter"
    chains: set[str] = set()
    for line in output.splitlines():
        if line.startswith("*"):
            table = line[1:].strip()
            continue
        if table != "filter":
            continue
        tokens = line.split()
        if line.startswith(":"):
            chain = line[1:].split()[0]
        elif len(tokens) >= 2 and tokens[0] in {"-P", "-N"}:
            chain = tokens[1]
        else:
            continue
        if chain in {"INPUT", "OUTPUT"}:
            chains.add(chain)
    return [
        {
            "id": f"{family}:filter:{chain}",
            "label": f"{family} filter → {chain}",
            "family": family,
            "table": "filter",
            "chain": chain,
            "direction": "in" if chain == "INPUT" else "out",
        }
        for chain in ("INPUT", "OUTPUT")
        if chain in chains
    ]


def scan_iptables_family(family: str) -> tuple[bool, list[dict[str, Any]], list[dict[str, str]], list[str]]:
    save_name = "ip6tables-save" if family == "ipv6" else "iptables-save"
    command_name = "ip6tables" if family == "ipv6" else "iptables"
    diagnostics: list[str] = []
    save_binary = find_system_command(save_name)
    if save_binary:
        code, output = run([save_binary], output_limit=5_000_000)
        if code == 0:
            return True, parse_iptables_rules(output, family), parse_iptables_filter_targets(output, family), diagnostics
        diagnostics.append(f"{save_name} exit {code}: {' '.join(output.split())[:300] or 'no output'}")
    command_binary = find_system_command(command_name)
    if not command_binary:
        diagnostics.append(f"{command_name} not found in PATH or standard system directories")
        return False, [], [], diagnostics
    rules: list[dict[str, Any]] = []
    targets: list[dict[str, str]] = []
    scanned = False
    for table in IPTABLES_TABLES:
        code, output = run([command_binary, "-w", "-t", table, "-S"], output_limit=5_000_000)
        if code != 0:
            if table == "filter":
                diagnostics.append(f"{command_name} filter scan exit {code}: {' '.join(output.split())[:300] or 'no output'}")
            continue
        scanned = True
        rules.extend(parse_iptables_rules(f"*{table}\n{output}\nCOMMIT", family))
        targets.extend(parse_iptables_filter_targets(f"*{table}\n{output}\nCOMMIT", family))
    return scanned, rules, targets, diagnostics


def windows_firewall_rules() -> tuple[int, str]:
    script = "$profiles=@(Get-NetFirewallProfile -ErrorAction Stop);$rows=@(Get-NetFirewallRule -PolicyStore ActiveStore|ForEach-Object{$r=$_;$p=$r|Get-NetFirewallPortFilter;$a=$r|Get-NetFirewallAddressFilter;[pscustomobject]@{id=$r.Name;backend='windows';name=$r.DisplayName;direction=([string]$r.Direction).ToLower();action=([string]$r.Action).ToLower();enabled=([bool]($r.Enabled -eq 'True'));protocol=([string]$p.Protocol).ToLower();localPort=([string]($p.LocalPort -join ','));remotePort=([string]($p.RemotePort -join ','));source=([string]($a.RemoteAddress -join ','));destination=([string]($a.LocalAddress -join ','));profile=([string]$r.Profile);raw=([string]$r.Description);removable=([bool]($r.PolicyStoreSourceType -eq 'Local'));reorderable=$false;spec=@{name=$r.Name;policyStoreSourceType=([string]$r.PolicyStoreSourceType)}}});$cap=[pscustomobject]@{profiles=@('Any')+@($profiles|ForEach-Object{$_.Name.ToString()});activeProfiles=@($profiles|Where-Object {$_.Enabled -eq 'True'}|ForEach-Object{$_.Name.ToString()});zones=@();defaultZone='';targets=@()};[pscustomobject]@{backend='windows';backends=@('windows');capabilities=$cap;rules=$rows}|ConvertTo-Json -Depth 7 -Compress"
    return powershell(script, timeout=300, output_limit=5_000_000)


def linux_firewall_rules() -> tuple[int, str]:
    diagnostics: list[str] = []
    firewall_cmd = find_system_command("firewall-cmd")
    if firewall_cmd:
        state_code, _ = run([firewall_cmd, "--state"])
        if state_code == 0:
            code, output = run([firewall_cmd, "--list-all-zones"], output_limit=5_000_000)
            if code == 0:
                rules = parse_firewalld_rules(output)
                zones = parse_firewalld_zones(output)
                default_code, default_output = run([firewall_cmd, "--get-default-zone"])
                default_zone = default_output.strip() if default_code == 0 and default_output.strip() in zones else ""
                capabilities = {"profiles": [], "activeProfiles": [], "zones": zones, "defaultZone": default_zone, "targets": []}
                return 0, json.dumps({"backend": "firewalld", "backends": ["firewalld"], "capabilities": capabilities, "rules": rules}, ensure_ascii=False, separators=(",", ":"))
    ufw = find_system_command("ufw")
    if ufw:
        code, output = run([ufw, "status", "numbered"], output_limit=5_000_000)
        if code == 0 and re.search(r"^Status:\s+active\s*$", output, re.IGNORECASE | re.MULTILINE):
            rules = parse_ufw_rules(output)
            capabilities = {"profiles": [], "activeProfiles": [], "zones": [], "defaultZone": "", "targets": []}
            return 0, json.dumps({"backend": "ufw", "backends": ["ufw"], "capabilities": capabilities, "rules": rules}, ensure_ascii=False, separators=(",", ":"))
        if code == 0:
            diagnostics.append("ufw is installed but inactive")
    nft = find_system_command("nft")
    if nft:
        code, output = run([nft, "-j", "-a", "list", "ruleset"], output_limit=5_000_000)
        if code == 0:
            rules = parse_nft_rules(output)
            capabilities = {"profiles": [], "activeProfiles": [], "zones": [], "defaultZone": "", "targets": parse_nft_filter_targets(output)}
            return 0, json.dumps({"backend": "nftables", "backends": ["nftables"], "capabilities": capabilities, "rules": rules}, ensure_ascii=False, separators=(",", ":"))
    rules: list[dict[str, Any]] = []
    families: list[str] = []
    targets: list[dict[str, str]] = []
    for family in ("ipv4", "ipv6"):
        scanned, family_rules, family_targets, family_diagnostics = scan_iptables_family(family)
        diagnostics.extend(f"{family}: {message}" for message in family_diagnostics)
        if scanned:
            rules.extend(family_rules)
            targets.extend(family_targets)
            families.append(family)
    if families:
        capabilities = {"profiles": [], "activeProfiles": [], "zones": [], "defaultZone": "", "targets": targets}
        return 0, json.dumps({"backend": "iptables", "backends": ["iptables"], "families": families, "capabilities": capabilities, "rules": rules}, ensure_ascii=False, separators=(",", ":"))
    warning = "No active or supported firewall backend found (firewalld, UFW, nftables, iptables)"
    if diagnostics:
        warning += ". Agent diagnostics: " + "; ".join(diagnostics)
    return 0, json.dumps({"backend": "", "backends": [], "rules": [], "warning": warning}, separators=(",", ":"))


def ps_literal(value: str) -> str:
    if not value or len(value) > 512 or any(ord(character) < 32 for character in value):
        raise ValueError("Invalid Windows firewall identifier")
    return "'" + value.replace("'", "''") + "'"


def nft_string_literal(value: str) -> str:
    if not value or len(value.encode("utf-8")) > 256 or any(ord(character) < 32 for character in value):
        raise ValueError("Invalid nftables string")
    return json.dumps(value, ensure_ascii=False)


def run_many(commands: list[list[str]], ignored_errors: tuple[str, ...] = ()) -> tuple[int, str]:
    results: list[str] = []
    for command in commands:
        code, output = run(command)
        results.append(output or f"{Path(command[0]).name}: OK")
        if code and not any(marker in output for marker in ignored_errors):
            return code, "\n".join(results)
    return 0, "\n".join(results)


def add_firewall_rule(parameters: dict[str, Any], inventory: dict[str, Any]) -> tuple[int, str]:
    values = firewall_parameters(parameters)
    backend = str(parameters.get("backend", "windows" if inventory["os_family"] == "windows" else "")).lower()
    if inventory["os_family"] == "windows":
        if backend != "windows":
            raise ValueError("Firewall backend does not match Windows")
        profile = str(parameters.get("profile", "Any"))
        if profile not in {"Any", "Domain", "Private", "Public"}:
            raise ValueError("Invalid Windows firewall profile")
        if values["local_port"] == "any" and values["direction"] != "out":
            raise ValueError("Inbound Windows firewall rules require a local port")
        direction = "Inbound" if values["direction"] == "in" else "Outbound"
        rule_action = "Allow" if values["action"] == "allow" else "Block"
        remote_port = "Any" if values["remote_port"] == "any" else str(values["remote_port"])
        script = f"New-NetFirewallRule -DisplayName {ps_literal('TramOps - ' + values['name'])} -Direction {direction} -Action {rule_action} -Enabled True -Profile {profile} -Protocol {values['protocol'].upper()} -LocalPort {values['local_port']} -RemotePort {remote_port} -RemoteAddress {ps_literal('Any' if values['source'] == 'any' else values['source'])} -LocalAddress {ps_literal('Any' if values['destination'] == 'any' else values['destination'])} -ErrorAction Stop|Select Name,DisplayName,Enabled,Direction,Action|ConvertTo-Json -Compress"
        return powershell(script)
    if backend == "ufw":
        binary = find_system_command("ufw")
        if not binary:
            return 1, "UFW is not installed"
        if values["local_port"] == "any":
            raise ValueError("UFW rules require a destination service port")
        command = [binary, "--force", "insert", "1", "allow" if values["action"] == "allow" else values["action"], values["direction"], "proto", values["protocol"], "from", values["source"]]
        if values["remote_port"] != "any": command += ["port", str(values["remote_port"])]
        command += ["to", values["destination"], "port", str(values["local_port"]), "comment", values["name"]]
        return run(command)
    if backend == "firewalld":
        binary = find_system_command("firewall-cmd")
        zone = str(parameters.get("zone", "public"))
        if not binary or not FIREWALL_OBJECT_RE.fullmatch(zone):
            raise ValueError("Invalid firewalld zone")
        zone_code, zone_output = run([binary, "--get-zones"])
        if zone_code or zone not in zone_output.split():
            raise ValueError("firewalld zone is no longer available; scan the server again")
        if values["direction"] != "in":
            raise ValueError("firewalld zone rules support inbound traffic only")
        family = str(parameters.get("family", "ipv6" if ":" in values["source"] or ":" in values["destination"] else "ipv4"))
        if family not in {"ipv4", "ipv6"}:
            raise ValueError("Invalid firewalld address family")
        if values["local_port"] == "any":
            raise ValueError("firewalld rules require a destination service port")
        for address in (values["source"], values["destination"]):
            if address != "any" and ipaddress.ip_network(address).version != (4 if family == "ipv4" else 6):
                raise ValueError("Firewall address does not match the selected IP family")
        parts = [f'rule family="{family}"']
        if values["source"] != "any": parts.append(f'source address="{values["source"]}"')
        if values["destination"] != "any": parts.append(f'destination address="{values["destination"]}"')
        if values["remote_port"] != "any": parts.append(f'source-port port="{values["remote_port"]}" protocol="{values["protocol"]}"')
        parts.append(f'port port="{values["local_port"]}" protocol="{values["protocol"]}"')
        parts.append("accept" if values["action"] == "allow" else "drop" if values["action"] == "deny" else "reject")
        rich_rule = " ".join(parts)
        return run_many([[binary, f"--zone={zone}", f"--add-rich-rule={rich_rule}"], [binary, "--permanent", f"--zone={zone}", f"--add-rich-rule={rich_rule}"]])
    if backend == "nftables":
        binary = find_system_command("nft")
        family = str(parameters.get("family", "inet")); table = str(parameters.get("table", "filter")); chain = str(parameters.get("chain", "input"))
        if not binary or family not in {"ip", "ip6", "inet"} or not FIREWALL_OBJECT_RE.fullmatch(table) or not FIREWALL_OBJECT_RE.fullmatch(chain):
            raise ValueError("Invalid nftables target")
        target_code, target_output = run([binary, "-j", "list", "ruleset"], output_limit=5_000_000)
        target = next((item for item in parse_nft_filter_targets(target_output) if item["family"] == family and item["table"] == table and item["chain"] == chain), None) if target_code == 0 else None
        if not target or target["direction"] != values["direction"]:
            raise ValueError("nftables filter chain is no longer available; scan the server again")
        if values["local_port"] == "any":
            raise ValueError("nftables rules require a destination service port")
        expected_version = {"ip": 4, "ip6": 6}.get(family)
        for address in (values["source"], values["destination"]):
            if address != "any" and expected_version and ipaddress.ip_network(address).version != expected_version:
                raise ValueError("Firewall address does not match the selected nftables family")
        command = [binary, "insert", "rule", family, table, chain]
        address_family = "ip6" if ":" in values["source"] or ":" in values["destination"] else "ip"
        if values["source"] != "any": command += [address_family, "saddr", values["source"]]
        if values["destination"] != "any": command += [address_family, "daddr", values["destination"]]
        if values["remote_port"] != "any": command += [values["protocol"], "sport", str(values["remote_port"])]
        verdict = "accept" if values["action"] == "allow" else "drop" if values["action"] == "deny" else "reject"
        command += [values["protocol"], "dport", str(values["local_port"]), verdict, "comment", nft_string_literal(f"TramOps - {values['name']}")]
        return run(command)
    if backend == "iptables":
        family = str(parameters.get("family", "ipv4")); table = str(parameters.get("table", "filter")); chain = str(parameters.get("chain", "INPUT" if values["direction"] == "in" else "OUTPUT"))
        binary = find_system_command("ip6tables" if family == "ipv6" else "iptables")
        if not binary or family not in {"ipv4", "ipv6"} or not FIREWALL_OBJECT_RE.fullmatch(table) or not FIREWALL_OBJECT_RE.fullmatch(chain):
            raise ValueError("Invalid iptables target")
        target_code, target_output = run([binary, "-w", "-t", table, "-S"], output_limit=5_000_000)
        target = next((item for item in parse_iptables_filter_targets(f"*{table}\n{target_output}\nCOMMIT", family) if item["chain"] == chain), None) if target_code == 0 else None
        if not target or target["direction"] != values["direction"]:
            raise ValueError("iptables filter chain is no longer available; scan the server again")
        if values["local_port"] == "any":
            raise ValueError("iptables rules require a destination service port")
        for address in (values["source"], values["destination"]):
            if address != "any" and ipaddress.ip_network(address).version != (4 if family == "ipv4" else 6):
                raise ValueError("Firewall address does not match the selected iptables family")
        command = [binary, "-w", "-t", table, "-I", chain, "1", "-p", values["protocol"], "--dport", str(values["local_port"])]
        if values["source"] != "any": command += ["-s", values["source"]]
        if values["destination"] != "any": command += ["-d", values["destination"]]
        if values["remote_port"] != "any": command += ["--sport", str(values["remote_port"])]
        target = "ACCEPT" if values["action"] == "allow" else "REJECT" if values["action"] == "reject" else "DROP"
        command += ["-m", "comment", "--comment", f"TramOps - {values['name']}", "-j", target]
        return run(command)
    raise ValueError("Unsupported firewall backend")


def add_firewall_rule_auto(parameters: dict[str, Any], inventory: dict[str, Any]) -> tuple[int, str]:
    values = firewall_parameters(parameters)
    requested_family = str(parameters.get("family", "ipv4")).lower()
    if requested_family not in {"ipv4", "ipv6"}:
        raise ValueError("Invalid common firewall IP family")
    resolved = dict(parameters)
    # An explicit all-address CIDR keeps nftables/iptables/UFW rules scoped to
    # the selected IP family instead of accidentally matching both families.
    if values["source"] == "any":
        resolved["source"] = "0.0.0.0/0" if requested_family == "ipv4" else "::/0"
    if values["destination"] == "any":
        resolved["destination"] = "any"

    if inventory["os_family"] == "windows":
        resolved.update({"backend": "windows", "profile": "Any"})
        scope = "Windows Firewall profile Any"
    else:
        scan_code, scan_output = linux_firewall_rules()
        if scan_code != 0:
            return scan_code, scan_output
        try:
            scan = json.loads(scan_output)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Cannot read the live firewall backend") from exc
        backend = str(scan.get("backend", "")).lower() if isinstance(scan, dict) else ""
        capabilities = scan.get("capabilities", {}) if isinstance(scan, dict) else {}
        capabilities = capabilities if isinstance(capabilities, dict) else {}
        resolved["backend"] = backend
        if backend == "firewalld":
            if values["direction"] != "in":
                raise ValueError("The selected server uses firewalld zones; common outbound rules are not supported")
            zones = [str(zone) for zone in capabilities.get("zones", []) if FIREWALL_OBJECT_RE.fullmatch(str(zone))]
            default_zone = str(capabilities.get("defaultZone", ""))
            zone = default_zone if default_zone in zones else (zones[0] if zones else "")
            if not zone:
                raise ValueError("firewalld did not report an available zone")
            resolved.update({"zone": zone, "family": requested_family})
            scope = f"firewalld zone {zone}"
        elif backend == "ufw":
            scope = "UFW active policy"
        elif backend == "nftables":
            raw_targets = capabilities.get("targets", [])
            targets = [target for target in raw_targets if isinstance(target, dict) and target.get("direction") == values["direction"]]
            family_order = ("inet", "ip") if requested_family == "ipv4" else ("inet", "ip6")
            target = next((target for family in family_order for target in targets if target.get("family") == family), None)
            if not target:
                raise ValueError("nftables did not report a compatible INPUT/OUTPUT filter chain")
            resolved.update({"family": str(target["family"]), "table": str(target["table"]), "chain": str(target["chain"])})
            scope = f"nftables {target['family']} {target['table']}/{target['chain']}"
        elif backend == "iptables":
            raw_targets = capabilities.get("targets", [])
            target = next((target for target in raw_targets if isinstance(target, dict) and target.get("direction") == values["direction"] and target.get("family") == requested_family), None)
            if not target:
                raise ValueError("iptables did not report a compatible INPUT/OUTPUT filter chain")
            resolved.update({"family": requested_family, "table": str(target["table"]), "chain": str(target["chain"])})
            scope = f"iptables {requested_family} {target['table']}/{target['chain']}"
        else:
            warning = str(scan.get("warning", "No active supported firewall backend found")) if isinstance(scan, dict) else "No active supported firewall backend found"
            raise ValueError(warning)

    code, output = add_firewall_rule(resolved, inventory)
    detail = f"Auto-selected {scope} from the live server state."
    return code, f"{detail}\n{output}" if output else detail


def remove_firewall_rules(parameters: dict[str, Any], inventory: dict[str, Any]) -> tuple[int, str]:
    rules = parameters.get("rules")
    if not isinstance(rules, list) or not 1 <= len(rules) <= 200 or any(not isinstance(rule, dict) for rule in rules):
        raise ValueError("Select between 1 and 200 firewall rules")
    backends = {str(rule.get("backend", "")).lower() for rule in rules}
    if len(backends) != 1:
        raise ValueError("Firewall rules must use the same backend")
    backend = next(iter(backends))
    if inventory["os_family"] == "windows":
        if backend != "windows": raise ValueError("Firewall backend does not match Windows")
        names = [ps_literal(str(rule.get("spec", {}).get("name", rule.get("id", "")))) for rule in rules]
        return powershell(f"@({','.join(names)})|ForEach-Object{{Remove-NetFirewallRule -Name $_ -ErrorAction Stop -Confirm:$false}}")
    commands: list[list[str]] = []
    if backend == "ufw":
        binary = find_system_command("ufw")
        if not binary: return 1, "UFW is not installed"
        numbers = sorted({int(rule.get("spec", {}).get("number", 0)) for rule in rules}, reverse=True)
        if not numbers or numbers[-1] < 1: raise ValueError("Invalid UFW rule number")
        commands = [[binary, "--force", "delete", str(number)] for number in numbers]
    elif backend == "firewalld":
        binary = find_system_command("firewall-cmd")
        if not binary: return 1, "firewalld is not installed"
        option_map = {"services": "service", "ports": "port", "protocols": "protocol", "source-ports": "source-port", "forward-ports": "forward-port", "icmp-blocks": "icmp-block", "rich rules": "rich-rule"}
        for rule in rules:
            spec = rule.get("spec", {}); zone = str(spec.get("zone", "")); kind = option_map.get(str(spec.get("type", ""))); value = str(spec.get("value", ""))
            if not kind or not FIREWALL_OBJECT_RE.fullmatch(zone) or not value or len(value) > 2048 or any(ord(c) < 32 for c in value): raise ValueError("Invalid firewalld rule")
            commands.append([binary, f"--zone={zone}", f"--remove-{kind}={value}"])
            commands.append([binary, "--permanent", f"--zone={zone}", f"--remove-{kind}={value}"])
    elif backend == "nftables":
        binary = find_system_command("nft")
        if not binary: return 1, "nftables is not installed"
        for rule in rules:
            spec = rule.get("spec", {}); family = str(spec.get("family", "")); table = str(spec.get("table", "")); chain = str(spec.get("chain", "")); handle = int(spec.get("handle", 0))
            if family not in {"ip", "ip6", "inet", "arp", "bridge", "netdev"} or not FIREWALL_OBJECT_RE.fullmatch(table) or not FIREWALL_OBJECT_RE.fullmatch(chain) or handle < 1: raise ValueError("Invalid nftables rule")
            commands.append([binary, "delete", "rule", family, table, chain, "handle", str(handle)])
    elif backend == "iptables":
        ordered = sorted(rules, key=lambda rule: (str(rule.get("spec", {}).get("family", "")), str(rule.get("spec", {}).get("table", "")), str(rule.get("spec", {}).get("chain", "")), -int(rule.get("spec", {}).get("index", 0))))
        for rule in ordered:
            spec = rule.get("spec", {}); family = str(spec.get("family", "")); table = str(spec.get("table", "")); chain = str(spec.get("chain", "")); index = int(spec.get("index", 0)); raw = str(rule.get("raw", "")); binary = find_system_command("ip6tables" if family == "ipv6" else "iptables")
            if not binary or family not in {"ipv4", "ipv6"} or not FIREWALL_OBJECT_RE.fullmatch(table) or not FIREWALL_OBJECT_RE.fullmatch(chain) or index < 1 or not raw: raise ValueError("Invalid iptables rule")
            code, output = run([binary, "-w", "-t", table, "-S", chain], output_limit=5_000_000)
            if code:
                return code, output
            current = next((item for item in parse_iptables_rules(f"*{table}\n{output}\nCOMMIT", family) if item["id"] == str(rule.get("id")) and item["raw"] == raw), None)
            if not current:
                raise ValueError("Firewall rules changed after the scan; scan again before deleting")
            if not current.get("removable"):
                raise ValueError("Docker-managed firewall rules cannot be deleted")
            commands.append([binary, "-t", table, "-D", chain, str(index)])
    else:
        raise ValueError("Unsupported firewall backend")
    return run_many(commands, ("NOT_ENABLED",)) if backend == "firewalld" else run_many(commands)


def require_reorder_rule(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Invalid firewall {label} rule")
    backend = str(value.get("backend", "")).lower()
    rule_id = str(value.get("id", ""))
    raw = str(value.get("raw", ""))
    spec = value.get("spec")
    if backend not in {"ufw", "nftables", "iptables"} or not rule_id or not raw or not isinstance(spec, dict):
        raise ValueError(f"Invalid firewall {label} rule")
    if len(rule_id) > 256 or len(raw) > 16_384 or any(ord(character) < 32 and character not in "\t" for character in raw):
        raise ValueError(f"Invalid firewall {label} rule")
    return value


def reorder_ufw_rule(parameters: dict[str, Any]) -> tuple[int, str]:
    binary = find_system_command("ufw")
    if not binary:
        return 1, "UFW is not installed"
    requested = require_reorder_rule(parameters.get("rule"), "source")
    before_requested = parameters.get("before")
    before = require_reorder_rule(before_requested, "target") if before_requested is not None else None
    if requested["backend"] != "ufw" or (before and before["backend"] != "ufw"):
        raise ValueError("Firewall reorder backend mismatch")
    code, output = run([binary, "status", "numbered"], output_limit=5_000_000)
    if code:
        return code, output
    current_rules = parse_ufw_rules(output)

    def current_match(candidate: dict[str, Any]) -> dict[str, Any]:
        match = next((rule for rule in current_rules if rule["id"] == str(candidate.get("id")) and rule["raw"] == str(candidate.get("raw"))), None)
        if not match:
            raise ValueError("Firewall rules changed after the scan; scan again before reordering")
        return match

    source = current_match(requested)
    target = current_match(before) if before else None
    if not source.get("reorderable"):
        raise ValueError("This UFW rule cannot be reconstructed safely")
    if target and source.get("orderGroup") != target.get("orderGroup"):
        raise ValueError("UFW rules can only be reordered within the same IP family")
    source_number = int(source["spec"]["number"])
    target_number = int(target["spec"]["number"]) if target else max(int(rule["spec"]["number"]) for rule in current_rules if rule.get("orderGroup") == source.get("orderGroup")) + 1
    if source_number == target_number or target_number == source_number + 1:
        return 0, "Firewall rule is already in the requested position"
    insert_arguments = source["spec"].get("insertArguments")
    if not isinstance(insert_arguments, list) or not insert_arguments or any(not isinstance(argument, str) for argument in insert_arguments):
        raise ValueError("This UFW rule cannot be reconstructed safely")
    insert_code, insert_output = run([binary, "--force", "insert", str(target_number), *insert_arguments])
    if insert_code:
        return insert_code, insert_output
    original_number = source_number + 1 if target_number <= source_number else source_number
    delete_code, delete_output = run([binary, "--force", "delete", str(original_number)])
    if delete_code:
        rollback_code, rollback_output = run([binary, "--force", "delete", str(target_number)])
        rollback = "rollback succeeded" if rollback_code == 0 else f"ROLLBACK FAILED: {rollback_output}"
        return delete_code, f"Could not remove the original UFW rule; {rollback}. {delete_output}"
    return 0, f"Moved UFW rule #{source_number} before position {target_number}"


def reorder_iptables_rule(parameters: dict[str, Any]) -> tuple[int, str]:
    requested = require_reorder_rule(parameters.get("rule"), "source")
    before_requested = parameters.get("before")
    before = require_reorder_rule(before_requested, "target") if before_requested is not None else None
    if requested["backend"] != "iptables" or (before and before["backend"] != "iptables"):
        raise ValueError("Firewall reorder backend mismatch")
    spec = requested["spec"]
    family = str(spec.get("family", "")); table = str(spec.get("table", "")); chain = str(spec.get("chain", "")); source_index = int(spec.get("index", 0))
    if family not in {"ipv4", "ipv6"} or not FIREWALL_OBJECT_RE.fullmatch(table) or not FIREWALL_OBJECT_RE.fullmatch(chain) or source_index < 1:
        raise ValueError("Invalid iptables source rule")
    if before:
        target_spec = before["spec"]
        if (str(target_spec.get("family", "")), str(target_spec.get("table", "")), str(target_spec.get("chain", ""))) != (family, table, chain):
            raise ValueError("iptables rules can only be reordered within the same table and chain")
        target_index = int(target_spec.get("index", 0))
    else:
        target_index = 0
    save_binary = find_system_command("ip6tables-save" if family == "ipv6" else "iptables-save")
    restore_binary = find_system_command("ip6tables-restore" if family == "ipv6" else "iptables-restore")
    if not save_binary or not restore_binary:
        command_binary = find_system_command("ip6tables" if family == "ipv6" else "iptables")
        if not command_binary:
            return 1, "iptables tools are not installed"
        code, output = run([command_binary, "-w", "-t", table, "-S", chain], output_limit=5_000_000)
        if code:
            return code, output
        current_rules = parse_iptables_rules(f"*{table}\n{output}\nCOMMIT", family)

        def current_match(candidate: dict[str, Any]) -> dict[str, Any]:
            match = next((rule for rule in current_rules if rule["id"] == str(candidate.get("id")) and rule["raw"] == str(candidate.get("raw"))), None)
            if not match:
                raise ValueError("Firewall rules changed after the scan; scan again before reordering")
            if not match.get("reorderable"):
                raise ValueError("Docker-managed firewall rules cannot be reordered")
            return match

        source = current_match(requested)
        target = current_match(before) if before else None
        target_index = int(target["spec"]["index"]) if target else len(current_rules) + 1
        if source_index == target_index or target_index == source_index + 1:
            return 0, "Firewall rule is already in the requested position"
        try:
            source_tokens = shlex.split(str(source["raw"]))
        except ValueError as exc:
            raise ValueError("Invalid iptables source rule") from exc
        if len(source_tokens) < 3 or source_tokens[:2] != ["-A", chain]:
            raise ValueError("Invalid iptables source rule")
        insert_code, insert_output = run([command_binary, "-w", "-t", table, "-I", chain, str(target_index), *source_tokens[2:]])
        if insert_code:
            return insert_code, insert_output
        original_index = source_index + 1 if target_index <= source_index else source_index
        delete_code, delete_output = run([command_binary, "-w", "-t", table, "-D", chain, str(original_index)])
        if delete_code:
            rollback_code, rollback_output = run([command_binary, "-w", "-t", table, "-D", chain, str(target_index)])
            rollback = "rollback succeeded" if rollback_code == 0 else f"ROLLBACK FAILED: {rollback_output}"
            return delete_code, f"Could not remove the original iptables rule; {rollback}. {delete_output}"
        return 0, f"Moved {family} {table}/{chain} rule #{source_index} before position {target_index}"
    code, output = run([save_binary], output_limit=5_000_000)
    if code:
        return code, output
    lines = output.splitlines()
    current_table = ""
    positions: list[int] = []
    for position, line in enumerate(lines):
        if line.startswith("*"):
            current_table = line[1:].strip()
        elif line == "COMMIT":
            current_table = ""
        elif current_table == table and line.startswith(f"-A {chain} "):
            positions.append(position)
    if source_index > len(positions) or lines[positions[source_index - 1]] != str(requested["raw"]):
        raise ValueError("Firewall rules changed after the scan; scan again before reordering")
    if before:
        if target_index < 1 or target_index > len(positions) or lines[positions[target_index - 1]] != str(before["raw"]):
            raise ValueError("Firewall rules changed after the scan; scan again before reordering")
    else:
        target_index = len(positions) + 1
    if source_index == target_index or target_index == source_index + 1:
        return 0, "Firewall rule is already in the requested position"
    ordered_lines = [lines[position] for position in positions]
    moved_line = ordered_lines.pop(source_index - 1)
    insertion_index = target_index - 1
    if source_index < target_index:
        insertion_index -= 1
    ordered_lines.insert(insertion_index, moved_line)
    for position, line in zip(positions, ordered_lines):
        lines[position] = line
    restore_code, restore_output = run_with_input([restore_binary], "\n".join(lines) + "\n")
    if restore_code:
        return restore_code, restore_output
    return 0, f"Moved {family} {table}/{chain} rule #{source_index} before position {target_index}"


def reorder_nftables_rule(parameters: dict[str, Any]) -> tuple[int, str]:
    binary = find_system_command("nft")
    if not binary:
        return 1, "nftables is not installed"
    requested = require_reorder_rule(parameters.get("rule"), "source")
    before_requested = parameters.get("before")
    before = require_reorder_rule(before_requested, "target") if before_requested is not None else None
    if requested["backend"] != "nftables" or (before and before["backend"] != "nftables"):
        raise ValueError("Firewall reorder backend mismatch")
    code, output = run([binary, "-j", "-a", "list", "ruleset"], output_limit=5_000_000)
    if code:
        return code, output
    current_rules = parse_nft_rules(output)

    def current_match(candidate: dict[str, Any]) -> dict[str, Any]:
        match = next((rule for rule in current_rules if rule["id"] == str(candidate.get("id")) and rule["raw"] == str(candidate.get("raw"))), None)
        if not match:
            raise ValueError("Firewall rules changed after the scan; scan again before reordering")
        return match

    source = current_match(requested)
    target = current_match(before) if before else None
    if target and source.get("orderGroup") != target.get("orderGroup"):
        raise ValueError("nftables rules can only be reordered within the same table and chain")
    if target and source["id"] == target["id"]:
        return 0, "Firewall rule is already in the requested position"
    source_spec = source["spec"]
    rule = {
        "family": source_spec["family"],
        "table": source_spec["table"],
        "chain": source_spec["chain"],
        "expr": json.loads(source["raw"]),
    }
    if source_spec.get("comment"):
        rule["comment"] = source_spec["comment"]
    command_name = "add"
    if target:
        rule["handle"] = int(target["spec"]["handle"])
        command_name = "insert"
    batch = {"nftables": [
        {command_name: {"rule": rule}},
        {"delete": {"rule": {
            "family": source_spec["family"],
            "table": source_spec["table"],
            "chain": source_spec["chain"],
            "handle": int(source_spec["handle"]),
        }}},
    ]}
    restore_code, restore_output = run_with_input([binary, "-j", "-f", "-"], json.dumps(batch, ensure_ascii=False, separators=(",", ":")))
    if restore_code:
        return restore_code, restore_output
    return 0, f"Moved nftables rule {source['id']}"


def reorder_firewall_rule(parameters: dict[str, Any], inventory: dict[str, Any]) -> tuple[int, str]:
    if inventory["os_family"] == "windows":
        raise ValueError("Windows Firewall does not support administrator-assigned rule ordering")
    requested = require_reorder_rule(parameters.get("rule"), "source")
    backend = str(requested.get("backend", "")).lower()
    if backend == "ufw":
        return reorder_ufw_rule(parameters)
    if backend == "nftables":
        return reorder_nftables_rule(parameters)
    if backend == "iptables":
        return reorder_iptables_rule(parameters)
    raise ValueError("This firewall backend does not support safe rule reordering")


def tunnel_url(config: Config, suffix: str) -> str:
    parsed = urlsplit(config.agent_endpoint)
    if parsed.scheme != "https" or not parsed.netloc:
        raise RuntimeError("Agent endpoint must use HTTPS before a tunnel can be opened")
    return f"wss://{parsed.netloc}{parsed.path}/tunnel/{suffix}"


def open_agent_websocket(config: Config, url: str, timeout: int = 30) -> websocket.WebSocket:
    if not config.server_ca_file:
        raise RuntimeError("Control-plane CA is not installed")
    headers = signed_headers(config, "GET", url)
    return websocket.create_connection(
        url,
        header=[f"{key}: {value}" for key, value in headers.items()],
        sslopt={
            "certfile": str(config.cert_file),
            "keyfile": str(config.key_file),
            "ca_certs": str(config.server_ca_file),
            "cert_reqs": ssl.CERT_REQUIRED,
            "check_hostname": True,
        },
        timeout=timeout,
        enable_multithread=True,
        suppress_origin=True,
    )


def tunnel_stream_worker(config: Config, instruction: dict[str, Any]) -> None:
    session_id = str(instruction.get("session_id", ""))
    protocol = str(instruction.get("protocol", ""))
    try:
        port = int(instruction.get("port", 0))
    except (TypeError, ValueError):
        LOG.warning("rejected tunnel instruction with an invalid port")
        return
    expected_port = {"ssh": 22, "rdp": 3389}.get(protocol)
    try:
        uuid.UUID(session_id)
    except ValueError:
        LOG.warning("rejected tunnel instruction with invalid session id")
        return
    if expected_port is None or port != expected_port:
        LOG.warning("rejected tunnel instruction protocol=%s port=%s", protocol, port)
        return

    stream_url = tunnel_url(config, f"stream/{session_id}?agent_id={config.agent_id}")
    with ACTIVE_TUNNELS_LOCK:
        if session_id in ACTIVE_TUNNELS or len(ACTIVE_TUNNELS) >= MAX_CONCURRENT_TUNNELS:
            LOG.warning("rejected tunnel %s because the local session limit was reached", session_id)
            return
        ACTIVE_TUNNELS.add(session_id)
    local_socket: socket.socket | None = None
    stream: websocket.WebSocket | None = None
    try:
        # The control plane never supplies a destination. The agent can connect
        # only to the SSH/RDP listener on the machine on which it is installed.
        local_socket = socket.create_connection(("127.0.0.1", expected_port), timeout=10)
        local_socket.settimeout(None)
        stream = open_agent_websocket(config, stream_url)
        stream.settimeout(None)
        stopped = threading.Event()

        def local_to_stream() -> None:
            try:
                while not stopped.is_set():
                    data = local_socket.recv(64 * 1024)
                    if not data:
                        break
                    stream.send_binary(data)
            except (OSError, websocket.WebSocketException):
                pass
            finally:
                stopped.set()
                with contextlib.suppress(Exception):
                    stream.close()

        sender = threading.Thread(target=local_to_stream, name=f"tram-tunnel-{session_id[:8]}", daemon=True)
        sender.start()
        while not stopped.is_set():
            opcode, data = stream.recv_data()
            if opcode == websocket.ABNF.OPCODE_CLOSE:
                break
            if opcode != websocket.ABNF.OPCODE_BINARY:
                raise RuntimeError("Tunnel stream received a non-binary frame")
            local_socket.sendall(data)
        stopped.set()
    except (OSError, RuntimeError, websocket.WebSocketException) as exc:
        LOG.warning("tunnel %s failed: %s", session_id, exc)
    finally:
        if stream:
            with contextlib.suppress(Exception):
                stream.close()
        if local_socket:
            with contextlib.suppress(Exception):
                local_socket.shutdown(socket.SHUT_RDWR)
            local_socket.close()
        with ACTIVE_TUNNELS_LOCK:
            ACTIVE_TUNNELS.discard(session_id)


def tunnel_control_loop(config: Config) -> None:
    backoff = 5
    while True:
        control: websocket.WebSocket | None = None
        try:
            ensure_server_ca(config)
            url = tunnel_url(config, f"control?agent_id={config.agent_id}")
            control = open_agent_websocket(config, url, timeout=60)
            control.send(json.dumps({"type": "ready", "agent_version": AGENT_VERSION}, separators=(",", ":")))
            LOG.info("agent reverse tunnel is online")
            backoff = 5
            while True:
                try:
                    message = control.recv()
                except websocket.WebSocketTimeoutException:
                    control.ping()
                    continue
                if not message:
                    raise websocket.WebSocketConnectionClosedException("Tunnel control channel closed")
                instruction = json.loads(message)
                if instruction.get("type") != "open":
                    raise RuntimeError("Unsupported tunnel instruction")
                threading.Thread(target=tunnel_stream_worker, args=(config, instruction), daemon=True).start()
        except (OSError, RuntimeError, ValueError, requests.RequestException, websocket.WebSocketException) as exc:
            LOG.warning("tunnel control unavailable: %s; retry in %ss", exc, backoff)
            time.sleep(backoff)
            backoff = min(60, backoff * 2)
        finally:
            if control:
                with contextlib.suppress(Exception):
                    control.close()


def local_malware_scan(path: Path, windows: bool) -> tuple[bool, str]:
    if windows:
        candidates: list[Path] = []
        platform_root = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "Microsoft/Windows Defender/Platform"
        if platform_root.is_dir():
            candidates.extend(sorted((item / "MpCmdRun.exe" for item in platform_root.iterdir()), reverse=True))
        candidates.append(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Windows Defender/MpCmdRun.exe")
        scanner = next((item for item in candidates if item.is_file()), None)
        if not scanner:
            return False, "Microsoft Defender scanner is unavailable"
        code, output = run([str(scanner), "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"], timeout=900)
        return code == 0, "Microsoft Defender: clean" if code == 0 else f"Microsoft Defender blocked the file (code {code}): {output[-1000:]}"
    scanner = shutil.which("clamscan")
    if not scanner:
        return False, "ClamAV clamscan is unavailable on this Linux server"
    code, output = run([scanner, "--no-summary", "--infected", str(path)], timeout=900)
    return code == 0, "ClamAV endpoint scan: clean" if code == 0 else f"ClamAV endpoint scan blocked the file (code {code}): {output[-1000:]}"


def deliver_file(config: Config, parameters: dict[str, Any], inventory: dict[str, Any]) -> tuple[int, str]:
    transfer_id = str(parameters.get("transfer_id", ""))
    filename = str(parameters.get("filename", ""))
    expected_sha256 = str(parameters.get("sha256", "")).lower()
    try:
        expected_size = int(parameters.get("size_bytes", 0))
    except (TypeError, ValueError):
        return 2, "Invalid file size metadata"
    try:
        uuid.UUID(transfer_id)
    except ValueError:
        return 2, "Invalid file transfer id"
    reserved_stem = filename.split(".", 1)[0].upper()
    if not TRANSFER_FILENAME_RE.fullmatch(filename) or filename.endswith((".", " ")) or reserved_stem in WINDOWS_RESERVED_FILENAMES:
        return 2, "Unsafe file name"
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or not 1 <= expected_size <= MAX_TRANSFER_BYTES:
        return 2, "Invalid file integrity metadata"

    windows = inventory["os_family"] == "windows"
    inbox = (Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "TramVanHanh/Inbox") if windows else Path("/var/lib/tram-agent/inbox")
    inbox.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(inbox, 0o700)
    destination = inbox / filename
    if destination.exists():
        return 3, "Destination file already exists; overwrite is forbidden"
    temporary = inbox / f".{transfer_id}.part"
    url = f"{config.agent_endpoint}/files/{transfer_id}?agent_id={config.agent_id}"
    headers = signed_headers(config, "GET", url)
    digest = hashlib.sha256()
    written = 0
    try:
        with requests.get(url, headers=headers, cert=(str(config.cert_file), str(config.key_file)), verify=config.tls_verify(), timeout=300, stream=True) as response:
            response.raise_for_status()
            if response.headers.get("X-Tram-SHA256", "").lower() != expected_sha256:
                raise RuntimeError("Control-plane hash header mismatch")
            with temporary.open("xb") as output:
                for chunk in response.iter_content(64 * 1024):
                    if not chunk:
                        continue
                    written += len(chunk)
                    if written > expected_size or written > MAX_TRANSFER_BYTES:
                        raise RuntimeError("Downloaded file exceeds approved size")
                    output.write(chunk)
                    digest.update(chunk)
                output.flush()
                os.fsync(output.fileno())
        if written != expected_size or not hmac.compare_digest(digest.hexdigest(), expected_sha256):
            raise RuntimeError("Downloaded file failed size or SHA-256 validation")
        with contextlib.suppress(OSError):
            os.chmod(temporary, 0o600)
        clean, scan_result = local_malware_scan(temporary, windows)
        if not clean:
            raise RuntimeError(scan_result)
        # Hard-link publication is atomic and refuses to overwrite an existing
        # destination. The temporary name is removed only after publication.
        os.link(temporary, destination)
        temporary.unlink()
        if windows:
            with contextlib.suppress(OSError):
                Path(str(destination) + ":Zone.Identifier").write_text("[ZoneTransfer]\r\nZoneId=3\r\n", encoding="ascii")
        return 0, json.dumps({"delivered": str(destination), "sha256": expected_sha256, "size": written, "endpoint_scan": scan_result}, ensure_ascii=False)
    except (OSError, RuntimeError, requests.RequestException) as exc:
        with contextlib.suppress(OSError):
            temporary.unlink()
        return 4, f"Secure file delivery failed: {exc}"


def json_rows(output: str) -> list[dict[str, Any]]:
    if not output.strip():
        return []
    parsed = json.loads(output)
    rows = parsed if isinstance(parsed, list) else [parsed]
    return [row for row in rows if isinstance(row, dict)]


def ps_quote(value: str) -> str:
    if any(ord(character) < 32 for character in value):
        raise ValueError("Invalid PowerShell string")
    return "'" + value.replace("'", "''") + "'"


def require_groups(parameters: dict[str, Any]) -> list[str]:
    raw = parameters.get("groups", [])
    if not isinstance(raw, list) or len(raw) > 100:
        raise ValueError("Invalid groups")
    groups = [str(group) for group in raw]
    if len(set(groups)) != len(groups) or any(not GROUP_RE.fullmatch(group) for group in groups):
        raise ValueError("Invalid groups")
    return groups


def linux_service_rows() -> tuple[int, str]:
    binary = find_system_command("systemctl")
    if not binary:
        return 127, "systemctl is not installed"
    files_code, files_output = run([binary, "list-unit-files", "--type=service", "--no-legend", "--no-pager"])
    units_code, units_output = run([binary, "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain"])
    if files_code != 0 and units_code != 0:
        return units_code or files_code, units_output or files_output
    startup: dict[str, str] = {}
    for line in files_output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and SERVICE_RE.fullmatch(fields[0]):
            startup[fields[0]] = fields[1]
    runtime: dict[str, tuple[str, str, str]] = {}
    for line in units_output.splitlines():
        fields = line.lstrip("● ").split(None, 4)
        if len(fields) >= 4 and SERVICE_RE.fullmatch(fields[0]):
            runtime[fields[0]] = (fields[2], fields[3], fields[4] if len(fields) > 4 else "")
    names = sorted(set(startup) | set(runtime), key=str.casefold)
    rows = []
    for name in names:
        active, sub, description = runtime.get(name, ("inactive", "dead", ""))
        rows.append({
            "name": name,
            "displayName": description or name,
            "status": active,
            "subState": sub,
            "startType": startup.get(name, "unknown"),
            "startsWithOs": startup.get(name, "") in {"enabled", "enabled-runtime", "static", "generated"},
        })
    return 0, json.dumps(rows, ensure_ascii=False, separators=(",", ":"))


def service_rows(windows: bool) -> tuple[int, str]:
    if windows:
        script = "Get-CimInstance Win32_Service|Sort-Object Name|ForEach-Object{[pscustomobject]@{name=$_.Name;displayName=$_.DisplayName;status=$_.State;subState=$_.Status;startType=$_.StartMode;startsWithOs=($_.StartMode -eq 'Auto')}}|ConvertTo-Json -Depth 3 -Compress"
        return powershell(script, output_limit=5_000_000)
    return linux_service_rows()


def linux_account_rows() -> dict[str, Any]:
    import grp
    import pwd
    passwd_binary = find_system_command("passwd")
    chage_binary = find_system_command("chage")
    users: list[dict[str, Any]] = []
    all_groups = list(grp.getgrall())
    group_names = {item.gr_gid: item.gr_name for item in all_groups}
    admin_groups = [name for name in ("sudo", "wheel") if any(group.gr_name == name for group in all_groups)]
    for item in pwd.getpwall():
        supplementary = sorted({group.gr_name for group in all_groups if item.pw_name in group.gr_mem})
        primary = group_names.get(item.pw_gid, str(item.pw_gid))
        groups = [primary, *[group for group in supplementary if group != primary]]
        locked = False
        password_status = "unknown"
        if passwd_binary:
            code, output = run([passwd_binary, "-S", item.pw_name])
            if code == 0:
                fields = output.split()
                if len(fields) >= 2:
                    password_status = fields[1]
                    locked = fields[1] in {"L", "LK", "NP"}
        account_expires = ""
        max_password_days: int | None = None
        if chage_binary:
            code, output = run([chage_binary, "-l", item.pw_name])
            if code == 0:
                for line in output.splitlines():
                    key, _, value = line.partition(":")
                    normalized = key.strip().lower()
                    if normalized == "account expires":
                        account_expires = "" if value.strip().lower() == "never" else value.strip()
                    elif normalized == "maximum number of days between password change":
                        with contextlib.suppress(ValueError):
                            max_password_days = int(value.strip())
        users.append({
            "name": item.pw_name,
            "uid": item.pw_uid,
            "home": item.pw_dir,
            "shell": item.pw_shell,
            "enabled": not locked,
            "locked": locked,
            "passwordStatus": password_status,
            "groups": groups,
            "isAdmin": item.pw_uid == 0 or any(group in admin_groups for group in groups),
            "accountExpires": account_expires,
            "maxPasswordDays": max_password_days,
            "protected": item.pw_uid < 1000,
        })
    groups = [{"name": item.gr_name, "gid": item.gr_gid, "members": sorted(item.gr_mem), "protected": item.gr_gid < 1000} for item in all_groups]
    return {"users": users, "groups": groups, "adminGroups": admin_groups}


def windows_account_rows() -> tuple[int, str]:
    script = "$groups=@(Get-LocalGroup|Sort-Object Name|ForEach-Object{$g=$_;$members=@(Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue|ForEach-Object{$_.Name.Split('\\')[-1]});[pscustomobject]@{name=$g.Name;members=$members;protected=($g.SID.Value -like 'S-1-5-32-*')}});$membership=@{};foreach($g in $groups){foreach($m in $g.members){if(-not $membership.ContainsKey($m)){$membership[$m]=@()};$membership[$m]+=,$g.name}};$lockouts=@{};Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction SilentlyContinue|ForEach-Object{$lockouts[$_.SID]=[bool]$_.Lockout};$admin=(Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue).Name;$default=(Get-LocalGroup -SID 'S-1-5-32-545' -ErrorAction SilentlyContinue).Name;$users=@(Get-LocalUser|Sort-Object Name|ForEach-Object{$rid=[int]$_.SID.Value.Split('-')[-1];[pscustomobject]@{name=$_.Name;enabled=$_.Enabled;locked=[bool]$lockouts[$_.SID.Value];lastLogon=$_.LastLogon;passwordExpires=$_.PasswordExpires;passwordLastSet=$_.PasswordLastSet;accountExpires=$_.AccountExpires;groups=@($membership[$_.Name]);isAdmin=(@($membership[$_.Name]) -contains $admin);protected=($rid -in @(500,501,503,504))}});[pscustomobject]@{users=$users;groups=$groups;adminGroups=@($admin);defaultGroups=@($default)}|ConvertTo-Json -Depth 6 -Compress"
    return powershell(script, output_limit=5_000_000)


def account_rows(windows: bool) -> tuple[int, str]:
    if windows:
        return windows_account_rows()
    return 0, json.dumps(linux_account_rows(), ensure_ascii=False, separators=(",", ":"))


def current_account_snapshot(windows: bool) -> dict[str, Any]:
    code, output = account_rows(windows)
    if code != 0:
        raise RuntimeError(output or "Cannot read local accounts")
    parsed = json.loads(output)
    return parsed if isinstance(parsed, dict) else {"users": [], "groups": [], "adminGroups": [], "defaultGroups": []}


def desired_account_groups(snapshot: dict[str, Any], requested: list[str], is_admin: bool, current: set[str] | None = None, *, include_defaults: bool = False) -> set[str]:
    available = {str(item.get("name")): item for item in snapshot.get("groups", []) if isinstance(item, dict)}
    if any(group not in available for group in requested):
        raise ValueError("A selected group no longer exists")
    admin_groups = {str(group) for group in snapshot.get("adminGroups", []) if group}
    protected_groups = {name for name, item in available.items() if item.get("protected")}
    protected_non_admin = protected_groups - admin_groups
    if any(group in protected_non_admin for group in requested):
        raise ValueError("Built-in groups are managed by the operating system")
    desired = set(requested) - admin_groups
    if is_admin and admin_groups:
        desired.add(sorted(admin_groups, key=str.casefold)[0])
    if current:
        desired.update(current & protected_non_admin)
    if include_defaults:
        desired.update(str(group) for group in snapshot.get("defaultGroups", []) if group)
    return desired


def validate_password(password: str, *, optional: bool = False) -> str:
    if optional and not password:
        return ""
    if not 12 <= len(password) <= 1024 or "\n" in password or "\r" in password or ":" in password:
        raise ValueError("Password must have at least 12 characters and cannot contain ':' or a newline")
    return password


def delete_local_users(parameters: dict[str, Any], windows: bool) -> tuple[int, str]:
    raw = parameters.get("usernames", [parameters.get("username")])
    if not isinstance(raw, list) or not 1 <= len(raw) <= 50:
        raise ValueError("Select between 1 and 50 users")
    names = [str(value) for value in raw]
    if len(set(names)) != len(names) or any(not NAME_RE.fullmatch(name) for name in names):
        raise ValueError("Invalid users")
    snapshot = current_account_snapshot(windows)
    by_name = {str(user.get("name")): user for user in snapshot.get("users", []) if isinstance(user, dict)}
    if any(name not in by_name or by_name[name].get("protected") for name in names):
        raise ValueError("A selected user no longer exists or is protected")
    commands: list[list[str]] = []
    if windows:
        script = ";".join(f"Remove-LocalUser -Name {ps_quote(name)} -ErrorAction Stop" for name in names)
        return powershell(script)
    binary = find_system_command("userdel")
    if not binary:
        return 127, "userdel is not installed"
    commands = [[binary, "--remove", name] for name in names]
    return run_many(commands)


def delete_local_groups(parameters: dict[str, Any], windows: bool) -> tuple[int, str]:
    raw = parameters.get("groups", [parameters.get("group")])
    if not isinstance(raw, list) or not 1 <= len(raw) <= 50:
        raise ValueError("Select between 1 and 50 groups")
    names = [str(value) for value in raw]
    if len(set(names)) != len(names) or any(not GROUP_RE.fullmatch(name) for name in names):
        raise ValueError("Invalid groups")
    snapshot = current_account_snapshot(windows)
    by_name = {str(group.get("name")): group for group in snapshot.get("groups", []) if isinstance(group, dict)}
    if any(name not in by_name or by_name[name].get("protected") for name in names):
        raise ValueError("A selected group no longer exists or is protected")
    if windows:
        return powershell(";".join(f"Remove-LocalGroup -Name {ps_quote(name)} -ErrorAction Stop" for name in names))
    binary = find_system_command("groupdel")
    if not binary:
        return 127, "groupdel is not installed"
    return run_many([[binary, name] for name in names])


def update_local_user(parameters: dict[str, Any], windows: bool) -> tuple[int, str]:
    username = require_name(parameters, "username")
    groups = require_groups(parameters)
    password = validate_password(str(parameters.get("password", "")), optional=True)
    enabled = bool(parameters.get("enabled", True))
    unlock = bool(parameters.get("unlock", False))
    is_admin = bool(parameters.get("is_admin", False))
    account_expires = str(parameters.get("account_expires", "")).strip()
    if account_expires and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", account_expires):
        raise ValueError("Invalid account expiration date")
    snapshot = current_account_snapshot(windows)
    users = {str(item.get("name")): item for item in snapshot.get("users", []) if isinstance(item, dict)}
    if username not in users or users[username].get("protected"):
        raise ValueError("The user no longer exists or is protected")
    current = {str(group) for group in users[username].get("groups", [])}
    desired = desired_account_groups(snapshot, groups, is_admin, current)
    if windows:
        statements = []
        if password:
            statements.append(f"$p=ConvertTo-SecureString {ps_quote(password)} -AsPlainText -Force;Set-LocalUser -Name {ps_quote(username)} -Password $p -ErrorAction Stop")
        statements.append(("Enable-LocalUser" if enabled else "Disable-LocalUser") + f" -Name {ps_quote(username)} -ErrorAction Stop")
        if unlock:
            statements.append(f"$u=[ADSI]('WinNT://'+$env:COMPUTERNAME+{ps_quote('/' + username + ',user')});$u.IsAccountLocked=$false;$u.SetInfo()")
        if account_expires:
            statements.append(f"Set-LocalUser -Name {ps_quote(username)} -AccountExpires ([datetime]{ps_quote(account_expires)}) -ErrorAction Stop")
        elif "account_expires" in parameters:
            statements.append(f"Set-LocalUser -Name {ps_quote(username)} -AccountNeverExpires $true -ErrorAction Stop")
        for group in sorted(desired - current):
            statements.append(f"Add-LocalGroupMember -Group {ps_quote(group)} -Member {ps_quote(username)} -ErrorAction Stop")
        for group in sorted(current - desired):
            statements.append(f"Remove-LocalGroupMember -Group {ps_quote(group)} -Member {ps_quote(username)} -ErrorAction Stop")
        return powershell(";".join(statements))
    primary = next(iter(users[username].get("groups", [])), "")
    gpasswd = find_system_command("gpasswd")
    usermod = find_system_command("usermod")
    chage = find_system_command("chage")
    if not gpasswd or not usermod:
        return 127, "usermod/gpasswd is not installed"
    commands = [[gpasswd, "-a", username, group] for group in sorted(desired - current)]
    commands += [[gpasswd, "-d", username, group] for group in sorted((current - desired) - {primary})]
    if unlock and not enabled:
        raise ValueError("Unlock requires the account to be enabled")
    commands.append([usermod, "--unlock" if enabled else "--lock", username])
    if account_expires:
        commands.append([usermod, "--expiredate", account_expires, username])
    elif "account_expires" in parameters:
        commands.append([usermod, "--expiredate", "", username])
    if "max_password_days" in parameters:
        max_days = int(parameters.get("max_password_days", -1))
        if not -1 <= max_days <= 99999 or not chage:
            raise ValueError("Invalid maximum password age")
        commands.append([chage, "-M", str(max_days), username])
    code, output = run_many(commands)
    if code == 0 and password:
        return run_with_input([find_system_command("chpasswd") or "/usr/sbin/chpasswd"], f"{username}:{password}\n")
    return code, output


def byte_value(value: Any) -> int:
    try:
        return max(0, int(float(str(value).strip() or "0")))
    except (TypeError, ValueError):
        return 0


def lvm_report(command: str, columns: str) -> list[dict[str, Any]]:
    binary = find_system_command(command)
    if not binary:
        return []
    code, output = run([binary, "--reportformat", "json", "--units", "b", "--nosuffix", "--options", columns], output_limit=5_000_000)
    if code != 0:
        return []
    try:
        reports = json.loads(output).get("report", [])
        if reports and isinstance(reports[0], dict):
            rows = reports[0].get(command[:-1], [])
            return rows if isinstance(rows, list) else []
    except (AttributeError, TypeError, ValueError):
        pass
    return []


def parted_free_regions(disk: str) -> list[dict[str, int]]:
    binary = find_system_command("parted")
    if not binary or not DEVICE_RE.fullmatch(disk):
        return []
    code, output = run([binary, "--machine", "--script", disk, "unit", "B", "print", "free"], output_limit=1_000_000)
    if code != 0:
        return []
    regions: list[dict[str, int]] = []
    for line in output.splitlines():
        fields = line.rstrip(";").split(":")
        if len(fields) < 5 or fields[4].strip().lower() != "free":
            continue
        try:
            start = int(fields[1].rstrip("B"))
            end = int(fields[2].rstrip("B"))
            size = int(fields[3].rstrip("B"))
        except ValueError:
            continue
        if size >= 4 * 1024 * 1024:
            regions.append({"startBytes": start, "endBytes": end, "sizeBytes": size})
    return regions


def normalize_mountpoints(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)] if value else []


def legacy_lsblk_devices(lsblk: str) -> tuple[int, list[dict[str, Any]] | str]:
    """Read util-linux 2.23 era lsblk output used by RHEL/Oracle Linux 7."""
    column_sets = (
        "NAME,KNAME,PKNAME,TYPE,FSTYPE,LABEL,UUID,SIZE,MOUNTPOINT,MODEL,RO,RM,PTTYPE",
        "NAME,KNAME,TYPE,FSTYPE,LABEL,UUID,SIZE,MOUNTPOINT,MODEL,RO,RM",
    )
    output = ""
    code = 1
    selected_columns: list[str] = []
    for columns in column_sets:
        code, output = run([lsblk, "--pairs", "--bytes", "--output", columns], output_limit=10_000_000)
        if code == 0:
            selected_columns = columns.lower().split(",")
            break
    if code != 0:
        return code, output
    flat: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            fields = dict(token.split("=", 1) for token in shlex.split(line) if "=" in token)
        except ValueError:
            continue
        lowered = {key.lower(): value for key, value in fields.items()}
        if not lowered.get("name"):
            continue
        lowered["path"] = "/dev/" + str(lowered.get("kname") or lowered["name"])
        lowered["mountpoints"] = [lowered.get("mountpoint")] if lowered.get("mountpoint") else []
        lowered["children"] = []
        flat.append(lowered)
    if not flat:
        return 2, "lsblk returned no block devices"
    by_name = {str(item.get("kname") or item.get("name")): item for item in flat}
    disks = [item for item in flat if item.get("type") == "disk"]
    for item in flat:
        if item in disks:
            continue
        parent_name = str(item.get("pkname") or "")
        if not parent_name and "pkname" not in selected_columns:
            name = str(item.get("kname") or item.get("name") or "")
            candidates = [candidate for candidate in by_name if candidate != name and name.startswith(candidate)]
            parent_name = max(candidates, key=len, default="")
        parent = by_name.get(parent_name)
        if parent is not None:
            parent.setdefault("children", []).append(item)
        else:
            disks.append(item)
    return 0, disks


def linux_storage_scan() -> tuple[int, str]:
    lsblk = find_system_command("lsblk")
    if not lsblk:
        return 127, "lsblk is not installed"
    columns = "NAME,KNAME,PATH,PKNAME,TYPE,FSTYPE,LABEL,UUID,SIZE,FSAVAIL,FSUSE%,MOUNTPOINTS,MODEL,SERIAL,TRAN,RO,RM,PTTYPE,PARTTYPE,PARTN,START,LOG-SEC"
    code, output = run([lsblk, "--json", "--bytes", "--tree", "--output", columns], output_limit=10_000_000)
    if code != 0:
        fallback = "NAME,KNAME,PATH,PKNAME,TYPE,FSTYPE,LABEL,UUID,SIZE,MOUNTPOINTS,MODEL,RO,RM,PTTYPE"
        code, output = run([lsblk, "--json", "--bytes", "--tree", "--output", fallback], output_limit=10_000_000)
    if code == 0:
        try:
            devices = json.loads(output).get("blockdevices", [])
        except (AttributeError, ValueError):
            return 2, "lsblk returned invalid JSON"
    else:
        legacy_code, legacy_result = legacy_lsblk_devices(lsblk)
        if legacy_code != 0:
            return legacy_code, str(legacy_result)
        devices = legacy_result
    pvs = lvm_report("pvs", "pv_name,vg_name,pv_size,pv_free")
    vgs = lvm_report("vgs", "vg_name,vg_size,vg_free,pv_count,lv_count")
    lvs = lvm_report("lvs", "lv_path,lv_name,vg_name,lv_size,data_percent,devices")
    pv_by_path = {str(item.get("pv_name", "")).strip(): item for item in pvs}
    vg_by_name: dict[str, dict[str, Any]] = {}
    for item in vgs:
        name = str(item.get("vg_name", "")).strip()
        if not name:
            continue
        vg_by_name[name] = {
            "name": name,
            "sizeBytes": byte_value(item.get("vg_size")),
            "freeBytes": byte_value(item.get("vg_free")),
            "physicalVolumes": [],
            "logicalVolumes": [],
        }
    for item in pvs:
        vg_name = str(item.get("vg_name", "")).strip()
        if vg_name in vg_by_name:
            vg_by_name[vg_name]["physicalVolumes"].append(str(item.get("pv_name", "")).strip())
    logical_volumes: list[dict[str, Any]] = []
    for item in lvs:
        path = str(item.get("lv_path", "")).strip()
        vg_name = str(item.get("vg_name", "")).strip()
        if not path or vg_name not in vg_by_name:
            continue
        logical = {
            "id": path,
            "path": path,
            "name": str(item.get("lv_name", "")).strip(),
            "vgName": vg_name,
            "sizeBytes": byte_value(item.get("lv_size")),
            "extendableBytes": vg_by_name[vg_name]["freeBytes"],
            "dataPercent": str(item.get("data_percent", "")).strip(),
            "devices": str(item.get("devices", "")).strip(),
            "filesystem": "",
            "mountpoints": [],
        }
        logical_volumes.append(logical)
        vg_by_name[vg_name]["logicalVolumes"].append(path)
    logical_by_path = {item["path"]: item for item in logical_volumes}
    free_by_disk: dict[str, list[dict[str, int]]] = {}

    def decorate(device: dict[str, Any], parent_disk: str = "") -> dict[str, Any]:
        path = str(device.get("path") or ("/dev/" + str(device.get("name", ""))))
        kind = str(device.get("type", ""))
        disk_path = path if kind == "disk" else parent_disk
        if kind == "disk":
            free_by_disk[path] = parted_free_regions(path)
        children = [decorate(child, disk_path) for child in device.get("children", []) if isinstance(child, dict)]
        mountpoints = normalize_mountpoints(device.get("mountpoints"))
        size = byte_value(device.get("size"))
        filesystem = str(device.get("fstype") or "")
        row: dict[str, Any] = {
            "id": path,
            "name": str(device.get("name", "")),
            "path": path,
            "parent": str(device.get("pkname") or ""),
            "type": kind,
            "filesystem": filesystem,
            "label": str(device.get("label") or ""),
            "uuid": str(device.get("uuid") or ""),
            "sizeBytes": size,
            "freeBytes": byte_value(device.get("fsavail")),
            "usedPercent": str(device.get("fsuse%") or ""),
            "mountpoints": mountpoints,
            "model": str(device.get("model") or "").strip(),
            "serial": str(device.get("serial") or "").strip(),
            "transport": str(device.get("tran") or ""),
            "readOnly": str(device.get("ro", "0")) in {"1", "true", "True"},
            "removable": str(device.get("rm", "0")) in {"1", "true", "True"},
            "partitionTable": str(device.get("pttype") or ""),
            "partitionType": str(device.get("parttype") or ""),
            "partitionNumber": byte_value(device.get("partn")),
            "startSector": byte_value(device.get("start")),
            "logicalSectorBytes": byte_value(device.get("log-sec")) or 512,
            "children": children,
            "extendableBytes": 0,
            "protected": "/" in mountpoints or "/boot" in mountpoints or "/boot/efi" in mountpoints,
        }
        if kind == "disk":
            regions = free_by_disk[path]
            row["freeRegions"] = regions
            row["unallocatedBytes"] = sum(region["sizeBytes"] for region in regions)
        if kind == "part" and disk_path:
            start = row["startSector"] * row["logicalSectorBytes"]
            end = start + size - 1
            for region in free_by_disk.get(disk_path, []):
                if 0 <= region["startBytes"] - end <= 2 * 1024 * 1024:
                    if filesystem in {"ext2", "ext3", "ext4", "xfs", "LVM2_member"}:
                        row["extendableBytes"] = region["sizeBytes"]
                    break
        pv = pv_by_path.get(path)
        if pv:
            row["lvm"] = {"vgName": str(pv.get("vg_name", "")).strip(), "pvFreeBytes": byte_value(pv.get("pv_free"))}
        if path in logical_by_path:
            logical_by_path[path]["filesystem"] = filesystem
            logical_by_path[path]["uuid"] = row["uuid"]
            logical_by_path[path]["mountpoints"] = mountpoints
            logical_by_path[path]["freeBytes"] = row["freeBytes"]
            logical_by_path[path]["protected"] = row["protected"]
        return row

    decorated = [decorate(device) for device in devices if isinstance(device, dict)]
    candidates: list[dict[str, Any]] = []

    def collect_candidates(row: dict[str, Any]) -> None:
        if row.get("type") == "part" and not row.get("filesystem") and not row.get("mountpoints") and not row.get("children"):
            candidates.append({"path": row["path"], "sizeBytes": row["sizeBytes"], "disk": row.get("parent", "")})
        for child in row.get("children", []):
            collect_candidates(child)

    for row in decorated:
        collect_candidates(row)
    result = {
        "platform": "linux",
        "disks": decorated,
        "volumeGroups": list(vg_by_name.values()),
        "logicalVolumes": logical_volumes,
        "lvmCandidates": candidates,
        "capabilities": {
            "partitionCreate": bool(find_system_command("parted")),
            "lvm": all(find_system_command(command) for command in ("pvs", "vgs", "lvs", "lvcreate", "vgcreate")),
        },
    }
    return 0, json.dumps(result, ensure_ascii=False, separators=(",", ":"))


def windows_storage_scan() -> tuple[int, str]:
    script = (
        "$minimumGap=[int64](16MB);$disks=@(Get-Disk|Sort-Object Number|ForEach-Object{$d=$_;"
        "$realParts=@(Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue|Sort-Object Offset|ForEach-Object{$p=$_;$v=$null;$supported=$null;"
        "try{$v=Get-Volume -Partition $p -ErrorAction Stop}catch{};try{$supported=Get-PartitionSupportedSize -DiskNumber $d.Number -PartitionNumber $p.PartitionNumber -ErrorAction Stop}catch{};"
        "$type=[string]$p.Type;$filesystem=if($v){[string]$v.FileSystem}else{''};$special=[bool]($p.IsHidden -or $type -match '(?i)system|reserved|recovery|oem|unknown');"
        "$extendable=if($supported -and -not $special -and $filesystem -match '^(?i:NTFS|ReFS)$'){[math]::Max(0,[int64]$supported.SizeMax-[int64]$p.Size)}else{0};"
        "$shrinkable=if($supported -and -not $special -and $filesystem -eq 'NTFS'){[math]::Max(0,[int64]$p.Size-[int64]$supported.SizeMin)}else{0};"
        "[pscustomobject]@{id=($d.Number.ToString()+':'+$p.PartitionNumber.ToString());diskNumber=[int]$d.Number;partitionNumber=[int]$p.PartitionNumber;driveLetter=if($p.DriveLetter){$p.DriveLetter.ToString()}else{''};"
        "type=$type;offsetBytes=[int64]$p.Offset;endOffsetBytes=[int64]$p.Offset+[int64]$p.Size;sizeBytes=[int64]$p.Size;extendableBytes=[int64]$extendable;shrinkableBytes=[int64]$shrinkable;"
        "filesystem=$filesystem;label=if($v){[string]$v.FileSystemLabel}else{''};freeBytes=if($v){[int64]$v.SizeRemaining}else{0};health=if($v){$v.HealthStatus.ToString()}else{''};"
        "path=$p.AccessPaths|Select-Object -First 1;protected=[bool]($p.IsBoot -or $p.IsSystem -or $special);resizeProtected=$special;resizeReason=if($special){'EFI, MSR, Recovery và OEM không được resize'}elseif($filesystem -notmatch '^(?i:NTFS|ReFS)$'){'Extend chỉ hỗ trợ NTFS/ReFS; Shrink chỉ hỗ trợ NTFS'}else{''}}});"
        "$segments=@();$cursor=[int64]0;foreach($part in $realParts){$offset=[int64]$part.offsetBytes;$gap=$offset-$cursor;if($gap -ge $minimumGap){$segments+=,[pscustomobject]@{id=('free:'+$d.Number+':'+$cursor);type='unallocated';name='Unallocated';offsetBytes=$cursor;endOffsetBytes=$offset;sizeBytes=$gap;freeBytes=$gap;protected=$true;resizeProtected=$true}};$segments+=,$part;$cursor=[math]::Max($cursor,[int64]$part.endOffsetBytes)};"
        "$tail=[int64]$d.Size-$cursor;if($tail -ge $minimumGap){$segments+=,[pscustomobject]@{id=('free:'+$d.Number+':'+$cursor);type='unallocated';name='Unallocated';offsetBytes=$cursor;endOffsetBytes=[int64]$d.Size;sizeBytes=$tail;freeBytes=$tail;protected=$true;resizeProtected=$true}};"
        "$unallocated=[int64](($segments|Where-Object{$_.type -eq 'unallocated'}|Measure-Object -Property sizeBytes -Sum).Sum);"
        "[pscustomobject]@{id=[string]$d.UniqueId;number=[int]$d.Number;name=[string]$d.FriendlyName;model=[string]$d.Model;serial=[string]$d.SerialNumber;sizeBytes=[int64]$d.Size;partitionTable=$d.PartitionStyle.ToString();"
        "health=$d.HealthStatus.ToString();operationalStatus=($d.OperationalStatus -join ', ');readOnly=[bool]$d.IsReadOnly;system=[bool]$d.IsSystem;boot=[bool]$d.IsBoot;unallocatedBytes=$unallocated;largestFreeExtentBytes=[int64]$d.LargestFreeExtent;partitions=@($segments)}});"
        "[pscustomobject]@{platform='windows';disks=$disks;volumeGroups=@();logicalVolumes=@();lvmCandidates=@();capabilities=@{partitionCreate=$true;partitionShrink=$true;lvm=$false}}|ConvertTo-Json -Depth 8 -Compress"
    )
    return powershell(script, timeout=180, output_limit=10_000_000)


def storage_scan(windows: bool) -> tuple[int, str]:
    return windows_storage_scan() if windows else linux_storage_scan()


def parsed_storage_scan(windows: bool) -> dict[str, Any]:
    code, output = storage_scan(windows)
    if code != 0:
        raise RuntimeError(output or "Cannot scan storage")
    parsed = json.loads(output)
    if not isinstance(parsed, dict):
        raise RuntimeError("Storage scan returned invalid data")
    return parsed


def storage_int(parameters: dict[str, Any], key: str, minimum: int = 1, maximum: int = 16 * 1024**4) -> int:
    try:
        value = int(parameters.get(key, 0))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid {key}") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"Invalid {key}")
    return value


def linux_mount_path(value: Any) -> str:
    path = str(value or "").rstrip("/") or "/"
    if not MOUNT_PATH_RE.fullmatch(path) or not any(path == root or path.startswith(root + "/") for root in ("/mnt", "/srv", "/data", "/opt", "/var/lib")):
        raise ValueError("Mount point must be below /mnt, /srv, /data, /opt or /var/lib")
    return path


def format_and_mount_linux(device: str, parameters: dict[str, Any]) -> tuple[int, str]:
    filesystem = str(parameters.get("filesystem", "ext4")).lower()
    if filesystem not in {"ext4", "xfs"}:
        raise ValueError("Only ext4 and xfs are supported for new Linux filesystems")
    label = str(parameters.get("label", "")).strip()
    if label and not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", label):
        raise ValueError("Invalid filesystem label")
    formatter = find_system_command(f"mkfs.{filesystem}")
    if not formatter:
        return 127, f"mkfs.{filesystem} is not installed"
    command = [formatter, "-F"] if filesystem == "ext4" else [formatter, "-f"]
    if label:
        command += ["-L", label]
    command.append(device)
    code, output = run(command, timeout=1800)
    if code != 0 or not parameters.get("mount_point"):
        return code, output
    mount_point = linux_mount_path(parameters.get("mount_point"))
    Path(mount_point).mkdir(parents=True, exist_ok=True)
    mount = find_system_command("mount")
    blkid = find_system_command("blkid")
    if not mount or not blkid:
        return 127, "mount/blkid is not installed"
    uuid_code, uuid_output = run([blkid, "-s", "UUID", "-o", "value", device])
    if uuid_code != 0 or not re.fullmatch(r"[A-Fa-f0-9-]{8,64}", uuid_output.strip()):
        return 2, "Cannot read filesystem UUID"
    code, mount_output = run([mount, device, mount_point])
    if code != 0:
        return code, mount_output
    fstab = Path("/etc/fstab")
    line = f"UUID={uuid_output.strip()} {mount_point} {filesystem} defaults 0 {2 if filesystem == 'ext4' else 0}"
    existing = fstab.read_text(errors="replace") if fstab.exists() else ""
    if f"UUID={uuid_output.strip()} " not in existing:
        with fstab.open("a", encoding="utf-8") as handle:
            if existing and not existing.endswith("\n"):
                handle.write("\n")
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    return 0, json.dumps({"device": device, "filesystem": filesystem, "mountPoint": mount_point}, separators=(",", ":"))


def find_linux_storage_node(scan: dict[str, Any], path: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    def walk(node: dict[str, Any], disk: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if node.get("path") == path:
            return node, disk
        for child in node.get("children", []):
            found, parent = walk(child, disk)
            if found:
                return found, parent
        return None, None
    for disk in scan.get("disks", []):
        found, parent = walk(disk, disk)
        if found:
            return found, parent
    return None, None


def extend_storage(parameters: dict[str, Any], windows: bool) -> tuple[int, str]:
    kind = str(parameters.get("kind", ""))
    add_bytes = storage_int(parameters, "add_bytes", 1024**2)
    if windows:
        if kind not in {"windows_partition", ""}:
            raise ValueError("Invalid Windows storage target")
        disk_number = storage_int(parameters, "disk_number", 0, 4096)
        partition_number = storage_int(parameters, "partition_number", 1, 4096)
        script = f"$p=Get-Partition -DiskNumber {disk_number} -PartitionNumber {partition_number} -ErrorAction Stop;$s=Get-PartitionSupportedSize -DiskNumber {disk_number} -PartitionNumber {partition_number} -ErrorAction Stop;$target=[int64]$p.Size+{add_bytes};if($target -gt [int64]$s.SizeMax){{throw 'Requested size exceeds live contiguous capacity'}};Resize-Partition -DiskNumber {disk_number} -PartitionNumber {partition_number} -Size $target -Confirm:$false -ErrorAction Stop;Get-Partition -DiskNumber {disk_number} -PartitionNumber {partition_number}|Select DiskNumber,PartitionNumber,DriveLetter,Size|ConvertTo-Json -Compress"
        return powershell(script, timeout=1800)
    scan = parsed_storage_scan(False)
    if kind == "linux_lv":
        path = str(parameters.get("path", ""))
        logical = next((item for item in scan.get("logicalVolumes", []) if item.get("path") == path), None)
        if not logical or add_bytes > byte_value(logical.get("extendableBytes")) or not DEVICE_RE.fullmatch(path):
            raise ValueError("Logical Volume changed or has insufficient free space")
        binary = find_system_command("lvextend")
        if not binary:
            return 127, "lvextend is not installed"
        return run([binary, "--resizefs", "--size", f"+{add_bytes}B", path], timeout=1800)
    if kind != "linux_partition":
        raise ValueError("Invalid Linux storage target")
    path = str(parameters.get("path", ""))
    node, disk = find_linux_storage_node(scan, path)
    if not node or not disk or node.get("type") != "part" or node.get("protected") or add_bytes > byte_value(node.get("extendableBytes")):
        raise ValueError("Partition changed, is protected or has insufficient contiguous space")
    number = byte_value(node.get("partitionNumber"))
    if not number:
        raise ValueError("Partition number is unavailable")
    start = byte_value(node.get("startSector")) * byte_value(node.get("logicalSectorBytes"))
    new_end = start + byte_value(node.get("sizeBytes")) + add_bytes - 1
    parted = find_system_command("parted")
    if not parted:
        return 127, "parted is not installed"
    code, output = run([parted, "--script", str(disk["path"]), "unit", "B", "resizepart", str(number), f"{new_end}B"], timeout=600)
    if code != 0:
        return code, output
    partprobe = find_system_command("partprobe")
    if partprobe:
        run([partprobe, str(disk["path"])], timeout=120)
    filesystem = str(node.get("filesystem", ""))
    if filesystem not in {"ext2", "ext3", "ext4", "xfs", "LVM2_member"}:
        raise ValueError("This filesystem cannot be extended safely by the Agent")
    if filesystem == "LVM2_member":
        pvresize = find_system_command("pvresize")
        return run([pvresize, path], timeout=600) if pvresize else (127, "pvresize is not installed")
    if filesystem in {"ext2", "ext3", "ext4"}:
        resize = find_system_command("resize2fs")
        return run([resize, path], timeout=1800) if resize else (127, "resize2fs is not installed")
    if filesystem == "xfs":
        mountpoints = node.get("mountpoints", [])
        grow = find_system_command("xfs_growfs")
        return run([grow, str(mountpoints[0])], timeout=1800) if grow and mountpoints else (2, "XFS must be mounted and xfs_growfs installed")
    return 2, f"Partition grew but filesystem {filesystem or 'unknown'} requires a manual grow operation"


def shrink_storage(parameters: dict[str, Any], windows: bool) -> tuple[int, str]:
    if not windows or str(parameters.get("kind", "")) != "windows_partition":
        raise ValueError("Shrink is supported only for Windows NTFS partitions")
    shrink_bytes = storage_int(parameters, "shrink_bytes", 16 * 1024**2)
    disk_number = storage_int(parameters, "disk_number", 0, 4096)
    partition_number = storage_int(parameters, "partition_number", 1, 4096)
    script = (
        f"$p=Get-Partition -DiskNumber {disk_number} -PartitionNumber {partition_number} -ErrorAction Stop;"
        "$v=$p|Get-Volume -ErrorAction Stop;$type=[string]$p.Type;"
        "if($p.IsHidden -or $type -match '(?i)system|reserved|recovery|oem|unknown'){throw 'EFI, MSR, Recovery and OEM partitions cannot be shrunk'};"
        "if([string]$v.FileSystem -ne 'NTFS'){throw 'Only NTFS partitions can be shrunk safely'};"
        f"$s=Get-PartitionSupportedSize -DiskNumber {disk_number} -PartitionNumber {partition_number} -ErrorAction Stop;$target=[int64]$p.Size-{shrink_bytes};"
        "if($target -lt [int64]$s.SizeMin){throw 'Requested shrink exceeds the live supported capacity; scan again'};"
        f"Resize-Partition -DiskNumber {disk_number} -PartitionNumber {partition_number} -Size $target -Confirm:$false -ErrorAction Stop;"
        f"$after=Get-Partition -DiskNumber {disk_number} -PartitionNumber {partition_number};"
        "[pscustomobject]@{diskNumber=[int]$after.DiskNumber;partitionNumber=[int]$after.PartitionNumber;driveLetter=[string]$after.DriveLetter;sizeBytes=[int64]$after.Size;unallocatedCreatedBytes="
        f"[int64]{shrink_bytes}}}|ConvertTo-Json -Compress"
    )
    return powershell(script, timeout=1800)


def create_storage(parameters: dict[str, Any], windows: bool) -> tuple[int, str]:
    kind = str(parameters.get("kind", ""))
    size_bytes = storage_int(parameters, "size_bytes", 16 * 1024**2)
    if windows:
        if kind != "windows_partition":
            raise ValueError("Invalid Windows storage create type")
        disk_number = storage_int(parameters, "disk_number", 0, 4096)
        filesystem = str(parameters.get("filesystem", "NTFS")).upper()
        if filesystem not in {"NTFS", "REFS"}:
            raise ValueError("Invalid Windows filesystem")
        label = str(parameters.get("label", "New Volume"))
        if not 1 <= len(label) <= 32 or any(ord(character) < 32 for character in label):
            raise ValueError("Invalid volume label")
        drive = str(parameters.get("drive_letter", "")).upper().rstrip(":")
        if drive and not re.fullmatch(r"[D-Z]", drive):
            raise ValueError("Invalid drive letter")
        assign = f"-DriveLetter {drive}" if drive else "-AssignDriveLetter"
        script = f"$d=Get-Disk -Number {disk_number} -ErrorAction Stop;if($d.IsReadOnly -or $d.IsOffline -or $d.LargestFreeExtent -lt {size_bytes}){{throw 'Disk changed or has insufficient unallocated space'}};$p=New-Partition -DiskNumber {disk_number} -Size {size_bytes} {assign} -ErrorAction Stop;$v=$p|Format-Volume -FileSystem {filesystem} -NewFileSystemLabel {ps_quote(label)} -Confirm:$false -Force -ErrorAction Stop;[pscustomobject]@{{diskNumber={disk_number};partitionNumber=$p.PartitionNumber;driveLetter=$p.DriveLetter;filesystem=$v.FileSystem;sizeBytes=[int64]$p.Size}}|ConvertTo-Json -Compress"
        return powershell(script, timeout=1800)
    scan = parsed_storage_scan(False)
    if kind == "linux_lv":
        vg_name = str(parameters.get("vg_name", ""))
        name = str(parameters.get("name", ""))
        if not GROUP_RE.fullmatch(vg_name) or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", name):
            raise ValueError("Invalid Logical Volume name")
        vg = next((item for item in scan.get("volumeGroups", []) if item.get("name") == vg_name), None)
        if not vg or size_bytes > byte_value(vg.get("freeBytes")):
            raise ValueError("Volume Group changed or has insufficient free space")
        lvcreate = find_system_command("lvcreate")
        if not lvcreate:
            return 127, "lvcreate is not installed"
        code, output = run([lvcreate, "--yes", "--size", f"{size_bytes}B", "--name", name, vg_name], timeout=900)
        if code != 0:
            return code, output
        return format_and_mount_linux(f"/dev/{vg_name}/{name}", parameters)
    if kind == "linux_vg":
        name = str(parameters.get("name", ""))
        device = str(parameters.get("device", ""))
        if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", name):
            raise ValueError("Invalid Volume Group name")
        candidate = next((item for item in scan.get("lvmCandidates", []) if item.get("path") == device), None)
        if not candidate or byte_value(candidate.get("sizeBytes")) < size_bytes:
            raise ValueError("LVM device changed or is not empty")
        pvcreate, vgcreate = find_system_command("pvcreate"), find_system_command("vgcreate")
        if not pvcreate or not vgcreate:
            return 127, "pvcreate/vgcreate is not installed"
        code, output = run([pvcreate, "--yes", device], timeout=600)
        return run([vgcreate, name, device], timeout=600) if code == 0 else (code, output)
    if kind != "linux_partition":
        raise ValueError("Invalid Linux storage create type")
    disk_path = str(parameters.get("disk", ""))
    start_bytes = storage_int(parameters, "start_bytes", 1024**2)
    disk = next((item for item in scan.get("disks", []) if item.get("path") == disk_path and item.get("type") == "disk"), None)
    if not disk or disk.get("readOnly") or disk.get("removable"):
        raise ValueError("Disk changed, is read-only or removable")
    region = next((item for item in disk.get("freeRegions", []) if start_bytes >= byte_value(item.get("startBytes")) and start_bytes + size_bytes - 1 <= byte_value(item.get("endBytes"))), None)
    if not region:
        raise ValueError("Selected unallocated region changed or is too small")
    parted = find_system_command("parted")
    if not parted:
        return 127, "parted is not installed"
    before = {str(child.get("path")) for child in disk.get("children", [])}
    fs_hint = "ext4" if str(parameters.get("filesystem", "ext4")) == "ext4" else "xfs"
    end_bytes = start_bytes + size_bytes - 1
    code, output = run([parted, "--script", "--align", "optimal", disk_path, "unit", "B", "mkpart", "primary", fs_hint, f"{start_bytes}B", f"{end_bytes}B"], timeout=600)
    if code != 0:
        return code, output
    partprobe = find_system_command("partprobe")
    if partprobe:
        run([partprobe, disk_path], timeout=120)
    time.sleep(1)
    refreshed = parsed_storage_scan(False)
    refreshed_disk = next((item for item in refreshed.get("disks", []) if item.get("path") == disk_path), {})
    created = next((child for child in refreshed_disk.get("children", []) if child.get("path") not in before and child.get("type") == "part"), None)
    if not created:
        return 2, "Partition was created but the kernel has not exposed the new device yet"
    return format_and_mount_linux(str(created["path"]), parameters)


def unmount_linux_storage(item: dict[str, Any]) -> str:
    mountpoints = [str(value) for value in item.get("mountpoints", []) if value]
    if item.get("protected") or any(path in {"/", "/boot", "/boot/efi"} for path in mountpoints):
        raise ValueError("System storage cannot be removed")
    device = str(item.get("path", ""))
    uuid_value = str(item.get("uuid", ""))
    if not uuid_value and DEVICE_RE.fullmatch(device):
        blkid = find_system_command("blkid")
        if blkid:
            code, output = run([blkid, "-s", "UUID", "-o", "value", device])
            if code == 0:
                uuid_value = output.strip()
    if mountpoints:
        umount = find_system_command("umount")
        if not umount:
            raise RuntimeError("umount is not installed")
        for mountpoint in sorted(mountpoints, key=len, reverse=True):
            code, output = run([umount, mountpoint], timeout=300)
            if code != 0:
                raise RuntimeError(output or f"Cannot unmount {mountpoint}")
    return uuid_value


def remove_linux_fstab_uuid(uuid_value: str) -> None:
    if not re.fullmatch(r"[A-Fa-f0-9-]{8,64}", uuid_value):
        return
    fstab = Path("/etc/fstab")
    if not fstab.exists():
        return
    existing = fstab.read_text(encoding="utf-8", errors="replace")
    lines = existing.splitlines(keepends=True)
    kept = [line for line in lines if not re.match(rf"^\s*UUID={re.escape(uuid_value)}(?:\s|$)", line, re.IGNORECASE)]
    if kept == lines:
        return
    temporary = fstab.with_name(".fstab.tram-agent.tmp")
    temporary.write_text("".join(kept), encoding="utf-8")
    os.chmod(temporary, fstab.stat().st_mode)
    os.replace(temporary, fstab)


def delete_storage(parameters: dict[str, Any], windows: bool) -> tuple[int, str]:
    kind = str(parameters.get("kind", ""))
    if windows:
        if kind != "windows_partition":
            raise ValueError("Invalid Windows storage delete type")
        disk_number = storage_int(parameters, "disk_number", 0, 4096)
        partition_number = storage_int(parameters, "partition_number", 1, 4096)
        script = f"$p=Get-Partition -DiskNumber {disk_number} -PartitionNumber {partition_number} -ErrorAction Stop;if($p.IsBoot -or $p.IsSystem){{throw 'Boot and system partitions are protected'}};Remove-Partition -DiskNumber {disk_number} -PartitionNumber {partition_number} -Confirm:$false -ErrorAction Stop"
        return powershell(script, timeout=600)
    scan = parsed_storage_scan(False)
    if kind == "linux_lv":
        path = str(parameters.get("path", ""))
        logical = next((item for item in scan.get("logicalVolumes", []) if item.get("path") == path), None)
        if not logical or logical.get("protected"):
            raise ValueError("Logical Volume changed or is protected")
        lvremove = find_system_command("lvremove")
        if not lvremove:
            return 127, "lvremove is not installed"
        uuid_value = unmount_linux_storage(logical)
        code, output = run([lvremove, "--yes", path], timeout=600)
        if code == 0:
            remove_linux_fstab_uuid(uuid_value)
        return code, output
    if kind == "linux_vg":
        name = str(parameters.get("name", ""))
        vg = next((item for item in scan.get("volumeGroups", []) if item.get("name") == name), None)
        if not vg or vg.get("logicalVolumes"):
            raise ValueError("Volume Group changed or still contains Logical Volumes")
        vgremove, pvremove = find_system_command("vgremove"), find_system_command("pvremove")
        if not vgremove or not pvremove:
            return 127, "vgremove/pvremove is not installed"
        code, output = run([vgremove, "--yes", name], timeout=600)
        if code != 0:
            return code, output
        cleanup_code, cleanup_output = run_many([[pvremove, "--yes", str(device)] for device in vg.get("physicalVolumes", [])])
        return cleanup_code, cleanup_output or output
    if kind != "linux_partition":
        raise ValueError("Invalid Linux storage delete type")
    path = str(parameters.get("path", ""))
    node, disk = find_linux_storage_node(scan, path)
    if not node or not disk or node.get("type") != "part" or node.get("protected") or node.get("children") or node.get("lvm"):
        raise ValueError("Partition changed, is in use or is protected")
    number = byte_value(node.get("partitionNumber"))
    parted = find_system_command("parted")
    if not parted or not number:
        return 127, "parted or partition number is unavailable"
    uuid_value = unmount_linux_storage(node)
    code, output = run([parted, "--script", str(disk["path"]), "rm", str(number)], timeout=600)
    if code == 0:
        remove_linux_fstab_uuid(uuid_value)
        partprobe = find_system_command("partprobe")
        if partprobe:
            run([partprobe, str(disk["path"])], timeout=120)
    return code, output


def _scan_updates_monolithic(inventory: dict[str, Any]) -> tuple[int, str]:
    if inventory["os_family"] == "windows":
        script = (
            "$ProgressPreference='SilentlyContinue';$rows=@();$policy=$null;$auPolicy=$null;try{$policy=Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -ErrorAction Stop}catch{};try{$auPolicy=Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -ErrorAction Stop}catch{};"
            "$updateSource=if($auPolicy.UseWUServer -eq 1 -and $policy.WUServer){'WSUS'}else{'Microsoft Update'};$updateServer=if($updateSource -eq 'WSUS'){[string]$policy.WUServer}else{''};$serviceStates=@{};$serviceActions=@{};foreach($serviceName in @('wuauserv','bits')){try{$service=Get-Service -Name $serviceName -ErrorAction Stop;if($service.Status -eq 'Stopped' -and $service.StartType -ne 'Disabled'){try{Start-Service -Name $serviceName -ErrorAction Stop;$service.WaitForStatus('Running',[TimeSpan]::FromSeconds(15));$serviceActions[$serviceName]='started'}catch{$serviceActions[$serviceName]=$_.Exception.Message}};$serviceStates[$serviceName]=(Get-Service -Name $serviceName -ErrorAction Stop).Status.ToString()}catch{$serviceStates[$serviceName]='missing'}};"
            "function AddWuaRows([object]$result,[string]$repository,[string]$serviceId=''){for($i=0;$i -lt $result.Updates.Count;$i++){$u=$result.Updates.Item($i);$identity=[string]$u.Identity.UpdateID;if($script:rows|Where-Object{$_.id -eq $identity}){continue};$kb=@($u.KBArticleIDs|ForEach-Object{[string]$_});$categories=@($u.Categories|ForEach-Object{[string]$_.Name});$severity=[string]$u.MsrcSeverity;if(-not $severity){if($u.Title -match '(?i)security|defender|malicious software|cumulative update'){$severity='security'}elseif($categories -match '(?i)driver'){$severity='driver'}else{$severity='normal'}};$architecture=if($u.Title -match '(?i)\\b(x64|x86|arm64)\\b'){$Matches[1].ToLower()}else{''};$version=if($kb.Count){(@($kb|ForEach-Object{'KB'+$_}) -join ', ')}else{[string]$u.Identity.RevisionNumber};$script:rows+=,[pscustomobject]@{id=$identity;revision=[int]$u.Identity.RevisionNumber;manager='wua';serviceId=$serviceId;name=[string]$u.Title;version=$version;architecture=$architecture;repository=$repository;severity=$severity;kb=$kb;categories=$categories;sizeBytes=[int64]$u.MaxDownloadSize;description=[string]$u.Description;rebootRequired=[bool]$u.RebootRequired;downloaded=[bool]$u.IsDownloaded;hidden=[bool]$u.IsHidden}}};"
            "$wuaError='';$wuaErrorCode='';$wuaCachedError='';$wuaCachedErrorCode='';$wuaCount=0;$wuaStatus='error';$wuaMode='cached';$r=$null;try{$cachedSession=New-Object -ComObject Microsoft.Update.Session;$cachedSession.ClientApplicationID='TramVanHanhAgent-Cache';$cachedSearcher=$cachedSession.CreateUpdateSearcher();$cachedSearcher.Online=$false;$r=$cachedSearcher.Search(\"IsInstalled=0 and IsHidden=0\");$wuaStatus='cached';AddWuaRows $r ($updateSource+' (cache cục bộ)')}catch{$wuaCachedError=$_.Exception.Message;$wuaCachedErrorCode=('0x{0:X8}' -f ($_.Exception.HResult -band 0xffffffff))};if($rows.Count -eq 0){try{$serviceManager=New-Object -ComObject Microsoft.Update.ServiceManager;foreach($updateService in @($serviceManager.Services)){try{$serviceSession=New-Object -ComObject Microsoft.Update.Session;$serviceSession.ClientApplicationID='TramVanHanhAgent-ServiceCache';$serviceSearcher=$serviceSession.CreateUpdateSearcher();$serviceSearcher.ServerSelection=3;$serviceSearcher.ServiceID=[string]$updateService.ServiceID;$serviceSearcher.Online=$false;$serviceResult=$serviceSearcher.Search(\"IsInstalled=0 and IsHidden=0\");AddWuaRows $serviceResult (([string]$updateService.Name)+' (cache cục bộ)') ([string]$updateService.ServiceID)}catch{}}}catch{}};if($rows.Count -eq 0){try{$onlineSession=New-Object -ComObject Microsoft.Update.Session;$onlineSession.ClientApplicationID='TramVanHanhAgent-Online';$searcher=$onlineSession.CreateUpdateSearcher();$searcher.Online=$true;$r=$searcher.Search(\"IsInstalled=0 and IsHidden=0\");$wuaStatus='ok';$wuaMode='online';AddWuaRows $r $updateSource}catch{$wuaError=$_.Exception.Message;$wuaErrorCode=('0x{0:X8}' -f ($_.Exception.HResult -band 0xffffffff));if($rows.Count -gt 0){$wuaStatus='cached';$wuaMode='cached'}}};$wuaCount=[int]$rows.Count;"
            "$ccmError='';$ccmCount=0;$ccmStatus='not_installed';try{$rootCcm=Get-CimInstance -Namespace 'root' -ClassName '__Namespace' -Filter \"Name='ccm'\" -ErrorAction Stop;if($rootCcm){$clientSdk=Get-CimInstance -Namespace 'root\\ccm' -ClassName '__Namespace' -Filter \"Name='ClientSDK'\" -ErrorAction Stop;if($clientSdk){$ccmStatus='ok';$ccm=@(Get-CimInstance -Namespace 'root\\ccm\\ClientSDK' -ClassName CCM_SoftwareUpdate -ErrorAction Stop|Where-Object{$_.ComplianceState -eq 0});$ccmCount=$ccm.Count;foreach($u in $ccm){$id=[string]$u.UpdateID;if(-not ($rows|Where-Object{$_.id -eq $id})){$article=[string]$u.ArticleID;$version=if($article){'KB'+$article}else{$id};$severity=if($u.BulletinID -or $u.Name -match '(?i)security|defender|malicious software|cumulative update'){'security'}else{'normal'};$rows+=,[pscustomobject]@{id=$id;revision=0;manager='configmgr';name=[string]$u.Name;version=$version;architecture='';repository='Microsoft Configuration Manager';severity=$severity;kb=if($article){@($article)}else{@()};categories=@();sizeBytes=[int64]$u.ContentSize;description=[string]$u.Description;rebootRequired=$false;downloaded=$false;hidden=$false}}}}}}catch{$ccmStatus='error';$ccmError=$_.Exception.Message};"
            "$manager=if($ccmCount -gt 0 -and $wuaCount -gt 0){'mixed'}elseif($ccmCount -gt 0){'configmgr'}else{'wua'};$currentScanComplete=[bool]($wuaStatus -eq 'ok' -or $ccmStatus -eq 'ok');[pscustomobject]@{platform='windows';manager=$manager;count=[int]$rows.Count;updates=@($rows);diagnostics=[pscustomobject]@{currentScanComplete=$currentScanComplete;wuaStatus=$wuaStatus;wuaMode=$wuaMode;wuaCount=$wuaCount;wuaError=$wuaError;wuaErrorCode=$wuaErrorCode;wuaCachedError=$wuaCachedError;wuaCachedErrorCode=$wuaCachedErrorCode;configMgrStatus=$ccmStatus;configMgrCount=$ccmCount;configMgrError=$ccmError;updateSource=$updateSource;updateServer=$updateServer;services=$serviceStates;serviceActions=$serviceActions}}|ConvertTo-Json -Depth 8 -Compress"
        )
        # Microsoft documents that WUA searches have no fixed completion time
        # and can vary widely with the update source and network. Three minutes
        # is too short for a first WSUS/Microsoft Update scan on Server 2022.
        return powershell(script, timeout=WINDOWS_UPDATE_SCAN_TIMEOUT_SECONDS, output_limit=10_000_000)
    if inventory.get("distribution_id") in {"ubuntu", "debian"}:
        apt = find_system_command("apt") or find_system_command("apt-get")
        if not apt:
            return 127, "apt is not installed"
        command = [apt, "list", "--upgradable"] if Path(apt).name == "apt" else [apt, "-s", "upgrade"]
        code, output = run(command, timeout=300, output_limit=5_000_000)
        if code != 0:
            return code, output
        rows: list[dict[str, Any]] = []
        if Path(apt).name == "apt":
            for line in output.splitlines():
                match = re.match(r"^([^/\s]+)/([^\s]+)\s+(\S+)\s+(\S+)\s+\[upgradable from: ([^\]]+)\]", line)
                if not match:
                    continue
                name, repository, version, architecture, current = match.groups()
                rows.append({"id": name, "name": name, "version": version, "currentVersion": current, "architecture": architecture, "repository": repository, "severity": "security" if "security" in repository.lower() else "normal", "sizeBytes": 0, "description": f"{name} {current} → {version}"})
        else:
            for line in output.splitlines():
                match = re.match(r"^Inst\s+(\S+)\s+(?:\[([^\]]+)\]\s+)?\((\S+)\s+([^\s)]+)", line)
                if match:
                    name, current, version, repository = match.groups()
                    rows.append({"id": name, "name": name, "version": version, "currentVersion": current or "", "architecture": "", "repository": repository, "severity": "security" if "security" in repository.lower() else "normal", "sizeBytes": 0, "description": f"{name} {current or ''} → {version}"})
        return 0, json.dumps({"platform": "linux", "manager": "apt", "updates": rows}, ensure_ascii=False, separators=(",", ":"))
    tool = find_system_command("dnf") or find_system_command("yum")
    if not tool:
        return 127, "dnf/yum is not installed"
    code, output = run([tool, "--quiet", "check-update"], timeout=300, output_limit=5_000_000)
    if code not in {0, 100}:
        return code, output
    rows = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 3 or not re.fullmatch(r"[A-Za-z0-9+_.:-]+", fields[0]):
            continue
        package_arch, version, repository = fields[:3]
        name, _, architecture = package_arch.rpartition(".")
        if not name:
            name, architecture = package_arch, ""
        rows.append({"id": package_arch, "name": name, "version": version, "currentVersion": "", "architecture": architecture, "repository": repository, "severity": "security" if "security" in repository.lower() else "normal", "sizeBytes": 0, "description": f"{package_arch} → {version} từ {repository}"})
    return 0, json.dumps({"platform": "linux", "manager": Path(tool).name, "updates": rows}, ensure_ascii=False, separators=(",", ":"))


def windows_update_query(*, online: bool, timeout: int) -> tuple[int, str]:
    online_literal = "$true" if online else "$false"
    mode = "online" if online else "cached"
    script = (
        "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';$rows=@();"
        "$policy=$null;$auPolicy=$null;try{$policy=Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -ErrorAction Stop}catch{};"
        "try{$auPolicy=Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -ErrorAction Stop}catch{};"
        "$source=if($auPolicy.UseWUServer -eq 1 -and $policy.WUServer){'WSUS'}else{'Microsoft Update'};"
        "foreach($serviceName in @('wuauserv','bits')){try{$service=Get-Service -Name $serviceName -ErrorAction Stop;if($service.Status -eq 'Stopped' -and $service.StartType -ne 'Disabled'){Start-Service -Name $serviceName -ErrorAction Stop}}catch{}};"
        "function AddRows([object]$result,[string]$repository,[string]$serviceId=''){for($i=0;$i -lt $result.Updates.Count;$i++){$u=$result.Updates.Item($i);$id=[string]$u.Identity.UpdateID;if($script:rows|Where-Object{$_.id -eq $id}){continue};$kb=@($u.KBArticleIDs|ForEach-Object{[string]$_});$categories=@($u.Categories|ForEach-Object{[string]$_.Name});$severity=[string]$u.MsrcSeverity;if(-not $severity){if($u.Title -match '(?i)security|defender|malicious software|cumulative update'){$severity='security'}elseif($categories -match '(?i)driver'){$severity='driver'}else{$severity='normal'}};$architecture=if($u.Title -match '(?i)\\b(x64|x86|arm64)\\b'){$Matches[1].ToLower()}else{''};$version=if($kb.Count){(@($kb|ForEach-Object{'KB'+$_}) -join ', ')}else{[string]$u.Identity.RevisionNumber};$script:rows+=,[pscustomobject]@{id=$id;revision=[int]$u.Identity.RevisionNumber;manager='wua';serviceId=$serviceId;name=[string]$u.Title;version=$version;architecture=$architecture;repository=$repository;severity=$severity;kb=$kb;categories=$categories;sizeBytes=[int64]$u.MaxDownloadSize;description=[string]$u.Description;rebootRequired=[bool]$u.RebootRequired;downloaded=[bool]$u.IsDownloaded;hidden=[bool]$u.IsHidden}}};"
        "$session=New-Object -ComObject Microsoft.Update.Session;$session.ClientApplicationID='TramVanHanhAgent-" + mode + "';$searcher=$session.CreateUpdateSearcher();$searcher.Online=" + online_literal + ";$result=$searcher.Search(\"IsInstalled=0 and IsHidden=0\");AddRows $result $source;"
        + ("" if online else "try{$manager=New-Object -ComObject Microsoft.Update.ServiceManager;foreach($service in @($manager.Services)){try{$serviceSession=New-Object -ComObject Microsoft.Update.Session;$serviceSearcher=$serviceSession.CreateUpdateSearcher();$serviceSearcher.ServerSelection=3;$serviceSearcher.ServiceID=[string]$service.ServiceID;$serviceSearcher.Online=$false;$serviceResult=$serviceSearcher.Search(\"IsInstalled=0 and IsHidden=0\");AddRows $serviceResult ([string]$service.Name) ([string]$service.ServiceID)}catch{}}}catch{};")
        + "[pscustomobject]@{platform='windows';manager='wua';count=[int]$rows.Count;updates=@($rows);diagnostics=[pscustomobject]@{currentScanComplete=" + online_literal + ";wuaStatus='" + mode + "';wuaMode='" + mode + "';wuaCount=[int]$rows.Count;updateSource=$source}}|ConvertTo-Json -Depth 8 -Compress"
    )
    return powershell(script, timeout=timeout, output_limit=10_000_000)


def windows_configmgr_updates() -> list[dict[str, Any]]:
    script = "$ErrorActionPreference='Stop';$rows=@();try{$updates=@(Get-CimInstance -Namespace 'root\\ccm\\ClientSDK' -ClassName CCM_SoftwareUpdate -ErrorAction Stop|Where-Object{$_.ComplianceState -eq 0});foreach($u in $updates){$article=[string]$u.ArticleID;$id=[string]$u.UpdateID;$rows+=,[pscustomobject]@{id=$id;revision=0;manager='configmgr';serviceId='';name=[string]$u.Name;version=if($article){'KB'+$article}else{$id};architecture='';repository='Microsoft Configuration Manager';severity=if($u.BulletinID -or $u.Name -match '(?i)security|defender|malicious software|cumulative update'){'security'}else{'normal'};kb=if($article){@($article)}else{@()};categories=@();sizeBytes=[int64]$u.ContentSize;description=[string]$u.Description;rebootRequired=$false;downloaded=$false;hidden=$false}};$rows|ConvertTo-Json -Depth 6 -Compress}catch{'[]'}"
    code, output = powershell(script, timeout=45, output_limit=5_000_000)
    if code != 0:
        return []
    try:
        return json_rows(output)
    except (TypeError, ValueError):
        return []


def scan_windows_updates() -> tuple[int, str]:
    configmgr_rows = windows_configmgr_updates()
    cache_code, cache_output = windows_update_query(online=False, timeout=60)
    cache: dict[str, Any] = {}
    if cache_code == 0:
        with contextlib.suppress(TypeError, ValueError):
            parsed = json.loads(cache_output)
            if isinstance(parsed, dict):
                cache = parsed
    wua_rows = [item for item in cache.get("updates", []) if isinstance(item, dict)]
    online_code = 0
    online_output = ""
    if not wua_rows:
        # DetectNow uses the update source selected by Windows policy. The
        # bounded online query then reads the same WUA catalogue as Settings.
        powershell("$ErrorActionPreference='SilentlyContinue';$au=New-Object -ComObject Microsoft.Update.AutoUpdate;$au.DetectNow()", timeout=30)
        online_code, online_output = windows_update_query(online=True, timeout=WINDOWS_UPDATE_SCAN_TIMEOUT_SECONDS)
        if online_code == 0:
            with contextlib.suppress(TypeError, ValueError):
                parsed = json.loads(online_output)
                if isinstance(parsed, dict):
                    cache = parsed
                    wua_rows = [item for item in parsed.get("updates", []) if isinstance(item, dict)]
        else:
            # An online WUA search can continue in wuauserv after the client
            # timeout. Re-read the local catalogue so completed detections are
            # still returned instead of failing the entire dashboard job.
            retry_code, retry_output = windows_update_query(online=False, timeout=60)
            if retry_code == 0:
                with contextlib.suppress(TypeError, ValueError):
                    parsed = json.loads(retry_output)
                    if isinstance(parsed, dict):
                        cache = parsed
                        wua_rows = [item for item in parsed.get("updates", []) if isinstance(item, dict)]
    merged: dict[str, dict[str, Any]] = {str(item.get("id")): item for item in [*wua_rows, *configmgr_rows] if item.get("id")}
    diagnostics = cache.get("diagnostics") if isinstance(cache.get("diagnostics"), dict) else {}
    diagnostics.update({
        "currentScanComplete": online_code == 0 if not wua_rows else bool(diagnostics.get("currentScanComplete", True)),
        "wuaCount": len(wua_rows),
        "wuaError": "" if online_code == 0 else (online_output or f"WUA scan exited with code {online_code}")[:1000],
        "configMgrCount": len(configmgr_rows),
        "configMgrStatus": "ok" if configmgr_rows else "not_installed_or_empty",
    })
    manager = "mixed" if wua_rows and configmgr_rows else "configmgr" if configmgr_rows else "wua"
    return 0, json.dumps({"platform": "windows", "manager": manager, "count": len(merged), "updates": list(merged.values()), "diagnostics": diagnostics}, ensure_ascii=False, separators=(",", ":"))


def scan_updates(inventory: dict[str, Any]) -> tuple[int, str]:
    if inventory["os_family"] == "windows":
        return scan_windows_updates()
    return _scan_updates_monolithic(inventory)


def install_updates(parameters: dict[str, Any], inventory: dict[str, Any]) -> tuple[int, str]:
    raw = parameters.get("updates", [])
    if not isinstance(raw, list) or not 1 <= len(raw) <= 100 or any(not isinstance(item, dict) for item in raw):
        raise ValueError("Select between 1 and 100 updates")
    scan_code, scan_output = scan_updates(inventory)
    if scan_code != 0:
        return scan_code, scan_output
    available = {str(item.get("id")): item for item in json.loads(scan_output).get("updates", []) if isinstance(item, dict)}
    selected: list[dict[str, Any]] = []
    for requested in raw:
        identifier = str(requested.get("id", ""))
        current = available.get(identifier)
        if not current or str(requested.get("version", "")) != str(current.get("version", "")):
            raise ValueError("An update changed or is no longer available; scan again")
        selected.append(current)
    if inventory["os_family"] == "windows":
        managers = {str(item.get("manager", "wua")) for item in selected}
        if len(managers) != 1:
            raise ValueError("Select Windows updates from one update manager per operation")
        if managers == {"configmgr"}:
            encoded = base64.b64encode(json.dumps([str(item["id"]) for item in selected]).encode()).decode()
            script = f"$wanted=@([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))|ConvertFrom-Json);$updates=@(Get-CimInstance -Namespace 'root\\ccm\\ClientSDK' -ClassName CCM_SoftwareUpdate -ErrorAction Stop|Where-Object{{$_.ComplianceState -eq 0 -and $wanted -contains [string]$_.UpdateID}});if($updates.Count -ne $wanted.Count){{throw 'Selected updates changed; scan again'}};$result=Invoke-CimMethod -Namespace 'root\\ccm\\ClientSDK' -ClassName CCM_SoftwareUpdatesManager -MethodName InstallUpdates -Arguments @{{CCMUpdates=[ciminstance[]]$updates}} -ErrorAction Stop;[pscustomobject]@{{manager='configmgr';returnValue=[int]$result.ReturnValue;count=$updates.Count}}|ConvertTo-Json -Compress"
            return powershell(script, timeout=7200)
        service_ids = {str(item.get("serviceId", "")) for item in selected}
        if len(service_ids) != 1:
            raise ValueError("Select Windows updates from one update service per operation")
        encoded = base64.b64encode(json.dumps([{"id": item["id"], "revision": item.get("revision", 0), "serviceId": item.get("serviceId", "")} for item in selected]).encode()).decode()
        script = f"$wanted=@( [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))|ConvertFrom-Json );foreach($serviceName in @('wuauserv','bits')){{try{{$service=Get-Service -Name $serviceName -ErrorAction Stop;if($service.Status -eq 'Stopped' -and $service.StartType -ne 'Disabled'){{Start-Service -Name $serviceName -ErrorAction Stop}}}}catch{{}}}};$s=New-Object -ComObject Microsoft.Update.Session;$s.ClientApplicationID='TramVanHanhAgent-Install';$searcher=$s.CreateUpdateSearcher();$serviceId=[string]$wanted[0].serviceId;if($serviceId){{$searcher.ServerSelection=3;$searcher.ServiceID=$serviceId}};$searcher.Online=$false;$q=$searcher.Search(\"IsInstalled=0 and IsHidden=0\");$c=New-Object -ComObject Microsoft.Update.UpdateColl;for($index=0;$index -lt $q.Updates.Count;$index++){{$u=$q.Updates.Item($index);$match=$wanted|Where-Object{{$_.id -eq $u.Identity.UpdateID -and [int]$_.revision -eq [int]$u.Identity.RevisionNumber}};if($match){{if(-not $u.EulaAccepted){{$u.AcceptEula()}};[void]$c.Add($u)}}}};if($c.Count -ne $wanted.Count){{throw 'Selected updates changed; scan again'}};$d=$s.CreateUpdateDownloader();$d.Updates=$c;$download=$d.Download();if($download.ResultCode -notin 2,3){{throw ('Download failed with WUA result '+$download.ResultCode)}};$i=$s.CreateUpdateInstaller();$i.Updates=$c;$r=$i.Install();[pscustomobject]@{{resultCode=$r.ResultCode;rebootRequired=$r.RebootRequired;count=$c.Count}}|ConvertTo-Json -Compress"
        return powershell(script, timeout=7200)
    if inventory.get("distribution_id") in {"ubuntu", "debian"}:
        apt_get = find_system_command("apt-get")
        if not apt_get:
            return 127, "apt-get is not installed"
        packages = []
        for item in selected:
            name, version = str(item["name"]), str(item["version"])
            if not PACKAGE_RE.fullmatch(name) or not PACKAGE_RE.fullmatch(version):
                raise ValueError("Invalid selected package")
            packages.append(f"{name}={version}")
        return run([apt_get, "-y", "--only-upgrade", "install", *packages], timeout=7200, output_limit=5_000_000)
    tool = find_system_command("dnf") or find_system_command("yum")
    packages = [f"{item['id']}-{item['version']}" for item in selected]
    if not tool or any(not PACKAGE_RE.fullmatch(package) for package in packages):
        raise ValueError("Invalid selected package or package manager unavailable")
    return run([tool, "-y", "upgrade", *packages], timeout=7200, output_limit=5_000_000)


def log_sources(windows: bool) -> tuple[int, str]:
    if windows:
        script = "$rows=@(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue|Where-Object{$_.IsEnabled}|Sort-Object LogName|Select-Object -First 300|ForEach-Object{[pscustomobject]@{id=$_.LogName;label=$_.LogName;type='eventlog';records=[int64]$_.RecordCount}});$rows|ConvertTo-Json -Depth 3 -Compress"
        return powershell(script, timeout=180, output_limit=5_000_000)
    rows = [{"id": "journal", "label": "System journal", "type": "journal", "records": 0}]
    root = Path("/var/log")
    if root.exists():
        with contextlib.suppress(OSError):
            for path in sorted(root.rglob("*"), key=lambda item: str(item).casefold()):
                if len(rows) >= 300:
                    break
                try:
                    resolved = path.resolve(strict=True)
                    if resolved.is_file() and str(resolved).startswith(str(root.resolve()) + os.sep) and resolved.stat().st_size <= 10 * 1024**3:
                        with resolved.open("rb") as sample_handle:
                            sample = sample_handle.read(4096)
                        if b"\x00" not in sample:
                            rows.append({"id": str(resolved), "label": str(resolved), "type": "file", "records": 0})
                except (OSError, RuntimeError):
                    continue
    return 0, json.dumps(rows, ensure_ascii=False, separators=(",", ":"))


def normalize_severity(value: Any, message: str = "") -> str:
    normalized = str(value or "").lower()
    combined = f"{normalized} {message.lower()}"
    if re.search(r"\b(?:critical|fatal|error|err|failed|failure)\b", combined) or normalized in {"1", "2", "3"}:
        return "error"
    if re.search(r"\b(?:warning|warn)\b", combined) or normalized == "4":
        return "warning"
    return "info"


def read_logs(parameters: dict[str, Any], windows: bool) -> tuple[int, str]:
    limit = min(500, max(1, int(parameters.get("limit", 500))))
    raw_sources = parameters.get("sources", ["System"] if windows else ["journal"])
    if not isinstance(raw_sources, list) or not 1 <= len(raw_sources) <= 20:
        raise ValueError("Select between 1 and 20 log sources")
    sources = [str(source) for source in raw_sources]
    per_source = max(1, limit // len(sources))
    rows: list[dict[str, Any]] = []
    if windows:
        if any(not re.fullmatch(r"[A-Za-z0-9_. /-]{1,180}", source) for source in sources):
            raise ValueError("Invalid Windows Event Log source")
        encoded = base64.b64encode(json.dumps(sources).encode()).decode()
        script = f"$sources=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))|ConvertFrom-Json);$available=@{{}};Get-WinEvent -ListLog * -ErrorAction SilentlyContinue|ForEach-Object{{$available[$_.LogName]=$true}};$rows=@(foreach($source in $sources){{if(-not $available.ContainsKey($source)){{throw 'Event Log source changed or is unavailable'}};Get-WinEvent -LogName $source -MaxEvents {per_source} -ErrorAction SilentlyContinue|ForEach-Object{{[pscustomobject]@{{timestamp=$_.TimeCreated.ToString('o');source=$source;severity=if($_.Level -le 2){{'error'}}elseif($_.Level -eq 3){{'warning'}}else{{'info'}};id=$_.Id;provider=$_.ProviderName;message=$_.Message}}}}}});$rows|Sort-Object timestamp -Descending|Select-Object -First {limit}|ConvertTo-Json -Depth 4 -Compress"
        return powershell(script, timeout=300, output_limit=10_000_000)
    available_code, available_output = log_sources(False)
    if available_code != 0:
        return available_code, available_output
    available = {str(item.get("id")) for item in json.loads(available_output) if isinstance(item, dict)}
    if any(source not in available for source in sources):
        raise ValueError("A log source changed or is outside the allowed server list")
    for source in sources:
        if source == "journal":
            journalctl = find_system_command("journalctl")
            if not journalctl:
                continue
            code, output = run([journalctl, "--no-pager", "-n", str(per_source), "-o", "json"], output_limit=8_000_000)
            if code != 0:
                continue
            for line in output.splitlines():
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                message = str(entry.get("MESSAGE", ""))
                raw_timestamp = str(entry.get("__REALTIME_TIMESTAMP", ""))
                try:
                    timestamp = datetime.fromtimestamp(int(raw_timestamp) / 1_000_000, UTC).isoformat()
                except (OSError, OverflowError, ValueError):
                    timestamp = raw_timestamp
                rows.append({"timestamp": timestamp, "source": str(entry.get("SYSLOG_IDENTIFIER") or entry.get("_SYSTEMD_UNIT") or "journal"), "severity": normalize_severity(entry.get("PRIORITY"), message), "message": message})
        else:
            path = Path(source)
            try:
                with path.open("r", encoding="utf-8", errors="replace") as handle:
                    lines = handle.readlines()[-per_source:]
            except OSError as exc:
                rows.append({"timestamp": "", "source": source, "severity": "error", "message": f"Cannot read log: {exc}"})
                continue
            for line in lines:
                message = line.rstrip("\r\n")
                rows.append({"timestamp": "", "source": source, "severity": normalize_severity("", message), "message": message})
    return 0, json.dumps(rows[-limit:], ensure_ascii=False, separators=(",", ":"))


def kill_processes(parameters: dict[str, Any]) -> tuple[int, str]:
    raw = parameters.get("processes", [])
    if not isinstance(raw, list) or not 1 <= len(raw) <= 100 or any(not isinstance(item, dict) for item in raw):
        raise ValueError("Select between 1 and 100 processes")
    protected_names = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "systemd", "init", "kthreadd", "tram-agent", "tram_agent.py"}
    selected: list[psutil.Process] = []
    for item in raw:
        pid = int(item.get("pid", 0))
        expected_name = str(item.get("name", ""))
        expected_created = float(item.get("created", 0))
        if pid <= 2 or pid in {os.getpid(), os.getppid()} or expected_name.lower() in protected_names:
            raise ValueError("A protected process cannot be terminated")
        try:
            process = psutil.Process(pid)
            if process.name() != expected_name or abs(process.create_time() - expected_created) > 0.01:
                raise ValueError("A selected process changed; scan again")
            selected.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            raise ValueError("A selected process changed or cannot be accessed") from exc
    for process in selected:
        process.terminate()
    _, alive = psutil.wait_procs(selected, timeout=8)
    for process in alive:
        process.kill()
    return 0, json.dumps({"terminated": [process.pid for process in selected]}, separators=(",", ":"))


def execute_job(action: str, parameters: dict[str, Any], inventory: dict[str, Any]) -> tuple[int, str]:
    if action not in ALLOWED_ACTIONS:
        return 126, "Action is not allowlisted by this agent"
    if action == "file.deliver":
        return 126, "File delivery requires the signed agent download channel"
    windows = inventory["os_family"] == "windows"
    if action == "inventory.collect":
        return 0, json.dumps(collect_inventory(), ensure_ascii=False, indent=2)
    if action == "service.list":
        return service_rows(windows)
    if action in {"service.start", "service.stop", "service.restart"}:
        name = require_name(parameters, "name", service=True)
        verb = action.split(".")[1]
        if windows:
            cmdlet = {"start": "Start-Service", "stop": "Stop-Service", "restart": "Restart-Service"}[verb]
            return powershell(f"{cmdlet} -Name '{name}' -ErrorAction Stop; Get-Service -Name '{name}'|Select Name,Status|ConvertTo-Json -Compress")
        systemctl = find_system_command("systemctl")
        return run([systemctl, verb, name], timeout=180) if systemctl else (127, "systemctl is not installed")
    if action == "group.create":
        group = require_group(parameters)
        if not windows and not LINUX_ACCOUNT_RE.fullmatch(group):
            raise ValueError("Linux group names must use lowercase letters, digits, '_', '.' or '-'")
        snapshot = current_account_snapshot(windows)
        if group in {str(item.get("name")) for item in snapshot.get("groups", []) if isinstance(item, dict)}:
            raise ValueError("Group already exists")
        if windows:
            return powershell(f"New-LocalGroup -Name {ps_quote(group)} -ErrorAction Stop")
        binary = find_system_command("groupadd")
        return run([binary, group]) if binary else (127, "groupadd is not installed")
    if action == "group.delete":
        return delete_local_groups(parameters, windows)
    if action == "user.list":
        code, output = account_rows(windows)
        return (code, json.dumps(json.loads(output).get("users", []), ensure_ascii=False, separators=(",", ":"))) if code == 0 else (code, output)
    if action == "group.list":
        code, output = account_rows(windows)
        return (code, json.dumps(json.loads(output).get("groups", []), ensure_ascii=False, separators=(",", ":"))) if code == 0 else (code, output)
    if action == "user.create":
        username = require_name(parameters, "username")
        account_pattern = WINDOWS_ACCOUNT_RE if windows else LINUX_ACCOUNT_RE
        if not account_pattern.fullmatch(username):
            raise ValueError("Username is not valid for this operating system")
        groups = require_groups(parameters)
        snapshot = current_account_snapshot(windows)
        if username in {str(item.get("name")) for item in snapshot.get("users", []) if isinstance(item, dict)}:
            raise ValueError("User already exists")
        groups = sorted(desired_account_groups(snapshot, groups, bool(parameters.get("is_admin", False)), include_defaults=windows), key=str.casefold)
        password = validate_password(str(parameters.get("password", "")))
        if windows:
            group_script = ";".join(f"Add-LocalGroupMember -Group {ps_quote(group)} -Member {ps_quote(username)} -ErrorAction Stop" for group in groups)
            script = f"try{{$p=ConvertTo-SecureString {ps_quote(password)} -AsPlainText -Force;New-LocalUser -Name {ps_quote(username)} -Password $p -PasswordNeverExpires:$false -UserMayNotChangePassword:$false -ErrorAction Stop;{group_script}}}catch{{if(Get-LocalUser -Name {ps_quote(username)} -ErrorAction SilentlyContinue){{Remove-LocalUser -Name {ps_quote(username)} -ErrorAction SilentlyContinue}};throw}}"
            return powershell(script)
        useradd = find_system_command("useradd")
        if not useradd:
            return 127, "useradd is not installed"
        command = [useradd, "--create-home", "--shell", "/bin/bash"]
        if groups:
            command += ["--groups", ",".join(str(group) for group in groups)]
        command.append(username)
        exit_code, output = run(command)
        if exit_code:
            return exit_code, output
        password_code, password_output = run_with_input([find_system_command("chpasswd") or "/usr/sbin/chpasswd"], f"{username}:{password}\n")
        if password_code:
            userdel = find_system_command("userdel")
            if userdel:
                run([userdel, "--remove", username])
        return password_code, password_output
    if action == "user.update":
        return update_local_user(parameters, windows)
    if action == "user.disable":
        username = require_name(parameters, "username")
        return powershell(f"Disable-LocalUser -Name '{username}' -ErrorAction Stop") if windows else run(["/usr/sbin/usermod", "--lock", "--expiredate", "1", username])
    if action == "user.enable":
        username = require_name(parameters, "username")
        return powershell(f"Enable-LocalUser -Name '{username}' -ErrorAction Stop") if windows else run(["/usr/sbin/usermod", "--unlock", "--expiredate", "", username])
    if action == "user.delete":
        return delete_local_users(parameters, windows)
    if action == "user.password.reset":
        username = require_name(parameters, "username")
        password = str(parameters.get("password", ""))
        if len(password) < 12 or "\n" in password or ":" in password:
            raise ValueError("Password must have at least 12 characters and cannot contain ':'")
        if windows:
            escaped = password.replace("'", "''")
            return powershell(f"$p=ConvertTo-SecureString '{escaped}' -AsPlainText -Force;Set-LocalUser -Name '{username}' -Password $p -ErrorAction Stop")
        return run_with_input(["/usr/sbin/chpasswd"], f"{username}:{password}\n")
    if action == "user.add_group":
        username = require_name(parameters, "username")
        group = require_group(parameters)
        return powershell(f"Add-LocalGroupMember -Group '{group}' -Member '{username}' -ErrorAction Stop") if windows else run(["/usr/sbin/usermod", "-aG", group, username])
    if action == "group.remove_user":
        username = require_name(parameters, "username")
        group = require_group(parameters)
        return powershell(f"Remove-LocalGroupMember -Group '{group}' -Member '{username}' -ErrorAction Stop") if windows else run(["/usr/bin/gpasswd", "-d", username, group])
    if action == "patch.scan":
        return scan_updates(inventory)
    if action == "patch.install":
        return install_updates(parameters, inventory)
    if action == "logs.sources":
        return log_sources(windows)
    if action == "logs.read":
        return read_logs(parameters, windows)
    if action == "process.list":
        processes: list[psutil.Process] = []
        for process in psutil.process_iter(["pid", "name", "create_time", "username"]):
            try:
                if process.info.get("name"):
                    process.cpu_percent(interval=None)
                    processes.append(process)
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
        # A short sample gives meaningful per-process CPU without making the
        # dashboard wait for the next scheduled Agent collection.
        time.sleep(0.35)
        rows = []
        for process in processes:
            try:
                memory = process.memory_info()
                rows.append({
                    "pid": process.pid,
                    "name": process.info["name"],
                    "created": process.info.get("create_time"),
                    "username": process.info.get("username"),
                    "cpuPercent": round(process.cpu_percent(interval=None), 2),
                    "memoryPercent": round(process.memory_percent(), 2),
                    "memoryBytes": int(memory.rss),
                })
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
        rows.sort(key=lambda item: (-float(item["cpuPercent"]), -int(item["memoryBytes"]), int(item["pid"])))
        return 0, json.dumps(rows[:2000], ensure_ascii=False)
    if action == "process.kill":
        return kill_processes(parameters)
    if action == "firewall.list":
        return windows_firewall_rules() if windows else linux_firewall_rules()
    if action == "firewall.rule.add":
        return add_firewall_rule(parameters, inventory)
    if action == "firewall.rule.add.auto":
        return add_firewall_rule_auto(parameters, inventory)
    if action == "firewall.rule.remove":
        return remove_firewall_rules(parameters, inventory)
    if action == "firewall.rule.reorder":
        return reorder_firewall_rule(parameters, inventory)
    if action == "storage.list":
        return storage_scan(windows)
    if action == "storage.extend":
        return extend_storage(parameters, windows)
    if action == "storage.shrink":
        return shrink_storage(parameters, windows)
    if action == "storage.create":
        return create_storage(parameters, windows)
    if action == "storage.delete":
        return delete_storage(parameters, windows)
    if action == "network.list":
        if windows:
            return powershell("Get-NetIPConfiguration|Select InterfaceAlias,InterfaceDescription,IPv4Address,IPv4DefaultGateway,DNSServer|ConvertTo-Json -Depth 4")
        return run(["/usr/sbin/ip", "-json", "address"])
    if action == "system.reboot":
        # Schedule the reboot so the agent can report a successful dispatch first.
        if windows:
            return run(["C:\\Windows\\System32\\shutdown.exe", "/r", "/t", "30", "/d", "p:4:1", "/c", "Tram Van Hanh approved reboot"])
        return run(["/usr/bin/systemd-run", "--on-active=30s", "/usr/bin/systemctl", "reboot"])
    return 126, "Unhandled action"


def enroll(config: Config, token: str) -> None:
    if not config.server_url:
        raise RuntimeError("server_url is required")
    if urlsplit(config.server_url).scheme != "https":
        raise RuntimeError("Enrollment must use HTTPS")
    key, csr = create_agent_identity(config.agent_id)
    enrollment_payload = {"token": token, "agent_id": config.agent_id, "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(), "inventory": collect_inventory()}
    for attempt in range(30):
        response = requests.post(config.server_url + "/api/v1/enroll", json=enrollment_payload, verify=config.tls_verify(), timeout=60)
        if response.status_code != 503 or attempt == 29:
            response.raise_for_status()
            break
        LOG.warning("control-plane CA is not ready; enrollment retry %s/30", attempt + 1)
        time.sleep(2)
    persist_enrollment(config, key, response.json())


def create_agent_identity(agent_id: str) -> tuple[ec.EllipticCurvePrivateKey, x509.CertificateSigningRequest]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Tram Van Hanh Agents")])).sign(key, hashes.SHA256())
    return key, csr


def harden_agent_directory(config: Config) -> None:
    config.key_file.parent.mkdir(parents=True, exist_ok=True)
    if platform.system().lower() == "windows":
        completed = subprocess.run(
            ["icacls.exe", str(config.key_file.parent), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if completed.returncode:
            raise RuntimeError("Cannot protect the Windows agent data directory")


def persist_enrollment(config: Config, key: ec.EllipticCurvePrivateKey, data: dict[str, Any]) -> None:
    harden_agent_directory(config)
    config.key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    config.cert_file.write_text(data["certificate"], encoding="utf-8")
    config.ca_file.write_text(data["ca_certificate"], encoding="utf-8")
    config.server_ca_file = config.path.parent / "server-ca.crt"
    config.server_ca_file.write_text(data["server_ca_certificate"], encoding="utf-8")
    config.agent_endpoint = data["agent_endpoint"].rstrip("/")
    config.save()
    try:
        os.chmod(config.key_file, 0o600)
        os.chmod(config.path, 0o600)
    except OSError:
        pass
    LOG.info("enrolled %s as %s; category=%s", config.agent_id, data["os_family"], data["category"])


def valid_server_origin(value: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise RuntimeError("Bootstrap server must be an origin-only HTTPS URL")
    return normalized


def install_pinned_server_ca(config: Config, certificate_pem: str, expected_sha256: str) -> None:
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError("Bootstrap package contains an invalid server CA") from exc
    actual = certificate.fingerprint(hashes.SHA256()).hex()
    if not hmac.compare_digest(actual, expected_sha256.lower()):
        raise RuntimeError("Bootstrap server CA fingerprint mismatch")
    harden_agent_directory(config)
    config.server_ca_file = config.path.parent / "server-ca.crt"
    config.server_ca_file.write_text(certificate_pem, encoding="utf-8")
    config.save()


def http_error_detail(response: requests.Response) -> str:
    try:
        payload = response.json()
        detail = payload.get("detail", "") if isinstance(payload, dict) else ""
    except (ValueError, TypeError):
        detail = ""
    if not detail:
        detail = response.text.strip()
    return re.sub(r"[\r\n\t]+", " ", str(detail)).strip()[:500]


def bootstrap_enroll(config: Config, package_id: str, package_secret: str) -> None:
    try:
        uuid.UUID(package_id)
    except ValueError as exc:
        raise RuntimeError("Invalid bootstrap package id") from exc
    if len(package_secret) < 32:
        raise RuntimeError("Invalid bootstrap package secret")
    key, csr = create_agent_identity(config.agent_id)
    payload = {
        "package_id": package_id,
        "package_secret": package_secret,
        "agent_id": config.agent_id,
        "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
        "inventory": collect_inventory(),
    }
    try:
        response = requests.post(config.server_url + "/api/v1/agent-bootstrap/claim", json=payload, verify=config.tls_verify(), timeout=90)
        response.raise_for_status()
    except requests.HTTPError as exc:
        response = exc.response
        status = response.status_code if response is not None else "unknown"
        detail = http_error_detail(response) if response is not None else ""
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"Bootstrap enrollment failed (HTTP {status}){suffix}") from exc
    except requests.RequestException as exc:
        raise RuntimeError(f"Bootstrap enrollment could not reach {config.server_url}: {exc}") from exc
    persist_enrollment(config, key, response.json())


def bootstrap_from_file(config: Config, source: Path) -> None:
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("Cannot read the bootstrap package") from exc
    if payload.get("version") != 1:
        raise RuntimeError("Unsupported bootstrap package version")
    config.server_url = valid_server_origin(str(payload.get("server_url", "")))
    bootstrap_tls_trust = str(payload.get("server_ca_sha256", ""))
    if bootstrap_tls_trust == "system":
        config.server_ca_file = None
    else:
        install_pinned_server_ca(config, str(payload.get("server_ca_certificate", "")), bootstrap_tls_trust)
    bootstrap_enroll(config, str(payload.get("package_id", "")), str(payload.get("package_secret", "")))


def parse_windows_installer_source(source: str) -> tuple[str, str, str, str]:
    filename = Path(source).name
    if not filename.lower().endswith(".msi"):
        raise RuntimeError("Windows bootstrap source is not an MSI")
    parts = filename[:-4].split("--")
    if len(parts) != 5 or parts[0] != "TramAgent":
        raise RuntimeError("This MSI does not contain a Tram Agent bootstrap claim")
    try:
        encoded_netloc, package_id, package_secret, ca_fingerprint = parts[1:]
        netloc = base64.urlsafe_b64decode(encoded_netloc + "=" * (-len(encoded_netloc) % 4)).decode("utf-8")
        uuid.UUID(package_id)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError("Windows bootstrap claim is malformed") from exc
    server_url = valid_server_origin(f"https://{netloc}")
    valid_tls_trust = ca_fingerprint == "system" or re.fullmatch(r"[0-9a-f]{64}", ca_fingerprint)
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", package_secret) or not valid_tls_trust:
        raise RuntimeError("Windows bootstrap claim is malformed")
    return server_url, package_id, package_secret, ca_fingerprint


def retrieve_server_ca_by_fingerprint(server_url: str, expected_sha256: str) -> str:
    parsed = urlsplit(server_url)
    # This first request intentionally has no PKI trust yet. Its only accepted
    # output is a CA certificate matching the SHA-256 pin carried by the MSI
    # filename. Every request after this one uses normal TLS verification.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=30, context=context)
    try:
        connection.request("GET", "/api/v1/agent-server-ca", headers={"Accept": "application/json"})
        response = connection.getresponse()
        body = response.read(256 * 1024)
        if response.status != 200:
            raise RuntimeError(f"Cannot retrieve the pinned dashboard CA (HTTP {response.status})")
        certificate_pem = str(json.loads(body).get("certificate", ""))
    except (OSError, ValueError, TypeError, http.client.HTTPException) as exc:
        raise RuntimeError("Cannot retrieve the pinned dashboard CA") from exc
    finally:
        connection.close()
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError("Dashboard returned an invalid bootstrap CA") from exc
    actual = certificate.fingerprint(hashes.SHA256()).hex()
    if not hmac.compare_digest(actual, expected_sha256):
        raise RuntimeError("Downloaded dashboard CA does not match the MSI pin")
    return certificate_pem


def bootstrap_from_windows_installer(config: Config, source: str) -> None:
    server_url, package_id, package_secret, ca_fingerprint = parse_windows_installer_source(source)
    config.server_url = server_url
    if ca_fingerprint == "system":
        config.server_ca_file = None
    else:
        certificate_pem = retrieve_server_ca_by_fingerprint(server_url, ca_fingerprint)
        install_pinned_server_ca(config, certificate_pem, ca_fingerprint)
    bootstrap_enroll(config, package_id, package_secret)


def ensure_server_ca(config: Config) -> None:
    if config.server_ca_file and config.server_ca_file.is_file():
        return
    if not config.server_url:
        raise RuntimeError("server_url is required to retrieve the server CA")
    if urlsplit(config.server_url).scheme != "https":
        raise RuntimeError("Control-plane CA bootstrap requires HTTPS")
    response = requests.get(config.server_url + "/api/v1/agent-server-ca", timeout=30)
    response.raise_for_status()
    certificate = response.json().get("certificate", "")
    if "BEGIN CERTIFICATE" not in certificate:
        raise RuntimeError("Control plane returned an invalid server CA")
    config.server_ca_file = config.path.parent / "server-ca.crt"
    config.server_ca_file.parent.mkdir(parents=True, exist_ok=True)
    config.server_ca_file.write_text(certificate, encoding="utf-8")
    config.save()
    LOG.info("installed control-plane server CA")


def post_result(config: Config, job_id: str, exit_code: int, output: str) -> None:
    url = f"{config.agent_endpoint}/jobs/{job_id}/result"
    body, headers = signed_request(config, "POST", url, {"status": "succeeded" if exit_code == 0 else "failed", "exit_code": exit_code, "output": output})
    response = requests.post(url, data=body, headers=headers, cert=(str(config.cert_file), str(config.key_file)), verify=config.tls_verify(), timeout=60)
    response.raise_for_status()


def execute_dispatched_job(config: Config, job: dict[str, Any], inventory: dict[str, Any]) -> tuple[int, str]:
    LOG.info("job %s action=%s", job["id"], job["action"])
    try:
        if job["action"] == "file.deliver":
            return deliver_file(config, job.get("parameters", {}), inventory)
        return execute_job(job["action"], job.get("parameters", {}), inventory)
    except Exception as exc:
        LOG.exception("job failed")
        return 1, f"{type(exc).__name__}: {exc}"


def loop(config: Config, once: bool = False) -> None:
    if not all(path.exists() for path in [config.cert_file, config.key_file, config.ca_file]):
        raise RuntimeError("Agent is not enrolled")
    last_inventory = 0.0
    inventory = collect_inventory()
    expensive_metrics_pending = False
    backoff = config.interval
    active_job: dict[str, Any] | None = None
    active_future: Future[tuple[int, str]] | None = None
    worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="tram-job")
    if not once:
        threading.Thread(target=tunnel_control_loop, args=(config,), name="tram-tunnel-control", daemon=True).start()
    try:
        while True:
            try:
                if active_job is not None and active_future is not None and active_future.done():
                    exit_code, output = active_future.result()
                    post_result(config, active_job["id"], exit_code, output)
                    active_job = None
                    active_future = None

                ensure_server_ca(config)
                timestamp = time.time()
                send_inventory = timestamp - last_inventory >= config.inventory_interval
                if send_inventory:
                    inventory = collect_inventory()
                include_expensive = expensive_metrics_pending and not send_inventory
                payload = {
                    "agent_id": config.agent_id,
                    "agent_version": AGENT_VERSION,
                    "active_job_id": active_job["id"] if active_job else None,
                    "inventory": inventory if send_inventory else None,
                    "metrics": collect_metrics(inventory, include_expensive=include_expensive),
                }
                url = config.agent_endpoint + "/checkin"
                body, headers = signed_request(config, "POST", url, payload)
                response = requests.post(url, data=body, headers=headers, cert=(str(config.cert_file), str(config.key_file)), verify=config.tls_verify(), timeout=240)
                response.raise_for_status()
                data = response.json()
                if send_inventory:
                    last_inventory = timestamp
                    expensive_metrics_pending = True
                elif include_expensive:
                    expensive_metrics_pending = False
                jobs = data.get("jobs", [])
                if active_job is None and jobs:
                    active_job = jobs[0]
                    if once:
                        exit_code, output = execute_dispatched_job(config, active_job, inventory)
                        post_result(config, active_job["id"], exit_code, output)
                        return
                    active_future = worker.submit(execute_dispatched_job, config, active_job, inventory)
                backoff = config.interval
                if once:
                    return
                checkin_interval = max(5, min(config.interval, int(data.get("checkin_interval_seconds", config.interval))))
                time.sleep(checkin_interval)
            except requests.RequestException as exc:
                detail = ""
                if exc.response is not None:
                    try:
                        detail = str(exc.response.json().get("detail", ""))
                    except (ValueError, AttributeError):
                        detail = exc.response.text.strip()[:500]
                suffix = f" ({detail})" if detail else ""
                LOG.warning("control plane unavailable: %s%s; retry in %ss", exc, suffix, backoff)
                if once:
                    raise
                time.sleep(backoff)
                backoff = min(300, backoff * 2)
            except Exception:
                LOG.exception("agent loop failed; retry in %ss", backoff)
                if once:
                    raise
                time.sleep(backoff)
                backoff = min(300, backoff * 2)
    finally:
        worker.shutdown(wait=once, cancel_futures=False)


def default_config_path() -> str:
    if platform.system().lower() == "windows":
        return str(Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "TramVanHanh/agent.json")
    return "/etc/tram-agent/agent.json"


def read_windows_bootstrap_source() -> str:
    if platform.system().lower() != "windows":
        raise RuntimeError("Windows bootstrap registry is unavailable on this platform")
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\TramVanHanh\Agent", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            value, _ = winreg.QueryValueEx(key, "BootstrapSource")
    except OSError as exc:
        raise RuntimeError("MSI bootstrap source is missing") from exc
    if not isinstance(value, str) or not value:
        raise RuntimeError("MSI bootstrap source is invalid")
    return value


def delete_windows_bootstrap_source() -> None:
    if platform.system().lower() != "windows":
        return
    import winreg

    with contextlib.suppress(OSError):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\TramVanHanh\Agent", 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.DeleteValue(key, "BootstrapSource")


def child_agent_command(config: Config, log_file: str | None) -> list[str]:
    executable = [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, str(Path(__file__).resolve())]
    command = [*executable, "--config", str(config.path)]
    if log_file:
        command.extend(["--log-file", log_file])
    command.append("run")
    return command


def run_windows_service(config: Config, log_file: str | None) -> None:
    if platform.system().lower() != "windows":
        raise RuntimeError("The service command is available only on Windows")
    import ctypes
    from ctypes import wintypes

    service_name = "TramVanHanhAgent"
    service_stop = threading.Event()
    service_child: subprocess.Popen[str] | None = None
    status_handle = wintypes.HANDLE()

    SERVICE_WIN32_OWN_PROCESS = 0x00000010
    SERVICE_STOPPED = 0x00000001
    SERVICE_START_PENDING = 0x00000002
    SERVICE_STOP_PENDING = 0x00000003
    SERVICE_RUNNING = 0x00000004
    SERVICE_ACCEPT_STOP = 0x00000001
    SERVICE_ACCEPT_SHUTDOWN = 0x00000004
    SERVICE_CONTROL_STOP = 0x00000001
    SERVICE_CONTROL_SHUTDOWN = 0x00000005

    class ServiceStatus(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
        ]

    handler_type = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID)
    service_main_type = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, handler_type, wintypes.LPVOID]
    advapi32.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    advapi32.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(ServiceStatus)]
    advapi32.SetServiceStatus.restype = wintypes.BOOL

    def set_status(state: int, *, exit_code: int = 0, wait_hint: int = 0) -> None:
        accepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN if state == SERVICE_RUNNING else 0
        status = ServiceStatus(SERVICE_WIN32_OWN_PROCESS, state, accepted, exit_code, 0, 0, wait_hint)
        if status_handle and not advapi32.SetServiceStatus(status_handle, ctypes.byref(status)):
            LOG.error("cannot update Windows service status: %s", ctypes.get_last_error())

    @handler_type
    def control_handler(control: int, _event_type: int, _event_data: int, _context: int) -> int:
        nonlocal service_child
        if control in {SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN}:
            set_status(SERVICE_STOP_PENDING, wait_hint=20_000)
            service_stop.set()
            if service_child and service_child.poll() is None:
                with contextlib.suppress(OSError):
                    service_child.terminate()
        return 0

    @service_main_type
    def service_main(_argc: int, _argv: ctypes.POINTER(wintypes.LPWSTR)) -> None:
        nonlocal status_handle, service_child
        status_handle = advapi32.RegisterServiceCtrlHandlerExW(service_name, control_handler, None)
        if not status_handle:
            return
        set_status(SERVICE_START_PENDING, wait_hint=120_000)
        exit_code = 0
        try:
            enrolled = all(path.exists() for path in (config.cert_file, config.key_file, config.ca_file))
            if not enrolled:
                bootstrap_from_windows_installer(config, read_windows_bootstrap_source())
            delete_windows_bootstrap_source()
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            service_child = subprocess.Popen(child_agent_command(config, log_file), creationflags=creation_flags, text=True)
            set_status(SERVICE_RUNNING)
            while not service_stop.wait(1):
                result = service_child.poll()
                if result is not None:
                    exit_code = result or 1
                    break
        except Exception:
            exit_code = 1
            LOG.exception("Windows service failed")
        finally:
            if service_child and service_child.poll() is None:
                with contextlib.suppress(OSError):
                    service_child.terminate()
                try:
                    service_child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(OSError):
                        service_child.kill()
            set_status(SERVICE_STOPPED, exit_code=exit_code)

    class ServiceTableEntry(ctypes.Structure):
        _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", service_main_type)]

    table = (ServiceTableEntry * 2)(ServiceTableEntry(service_name, service_main), ServiceTableEntry(None, service_main_type()))
    advapi32.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(ServiceTableEntry)]
    advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
    if not advapi32.StartServiceCtrlDispatcherW(table):
        raise RuntimeError(f"Cannot connect to Windows Service Control Manager ({ctypes.get_last_error()})")


def main() -> int:
    parser = argparse.ArgumentParser(description="Trạm Vận Hành agent")
    parser.add_argument("--config", default=default_config_path())
    parser.add_argument("--log-file")
    sub = parser.add_subparsers(dest="command", required=True)
    enrollment = sub.add_parser("enroll")
    enrollment.add_argument("--server", required=True)
    enrollment.add_argument("--token")
    enrollment.add_argument("--server-ca", help="PEM CA used to verify a private/internal dashboard certificate")
    bootstrap_parser = sub.add_parser("bootstrap")
    bootstrap_parser.add_argument("--file", required=True, help="One-time bootstrap JSON generated by the dashboard")
    sub.add_parser("diagnose", help="Print detected platform inventory without enrolling or changing the host")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--once", action="store_true")
    sub.add_parser("service")
    args = parser.parse_args()
    configure_logging(args.log_file)
    config = Config(args.config)
    if args.command == "diagnose":
        inventory = collect_inventory()
        print(json.dumps({
            "hostname": inventory["hostname"],
            "os_family": inventory["os_family"],
            "os_name": inventory["os_name"],
            "os_version": inventory["os_version"],
            "distribution_id": inventory["distribution_id"],
            "architecture": inventory["architecture"],
            "agent_version": inventory["agent_version"],
        }, ensure_ascii=False, separators=(",", ":")))
        return 0
    if args.command == "enroll":
        config.server_url = args.server.rstrip("/")
        if args.server_ca:
            certificate = Path(args.server_ca).read_text(encoding="utf-8")
            if "BEGIN CERTIFICATE" not in certificate:
                raise RuntimeError("--server-ca is not a PEM certificate")
            config.server_ca_file = config.path.parent / "server-ca.crt"
            config.server_ca_file.parent.mkdir(parents=True, exist_ok=True)
            config.server_ca_file.write_text(certificate, encoding="utf-8")
            config.save()
        token = args.token or getpass.getpass("Enrollment token: ")
        enroll(config, token)
        return 0
    if args.command == "bootstrap":
        bootstrap_from_file(config, Path(args.file))
        return 0
    if args.command == "service":
        run_windows_service(config, args.log_file)
        return 0
    loop(config, args.once)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        LOG.error("%s", exc)
        raise SystemExit(1) from None
