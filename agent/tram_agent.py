from __future__ import annotations

import argparse
import base64
import contextlib
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
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,160}$")
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
ACTIVE_TUNNELS: set[str] = set()
ACTIVE_TUNNELS_LOCK = threading.Lock()
ALLOWED_ACTIONS = {
    "inventory.collect", "service.list", "service.restart", "service.start", "service.stop",
    "user.create", "user.disable", "user.enable", "user.delete", "user.password.reset",
    "group.create", "group.delete", "user.add_group", "patch.scan",
    "patch.install_security", "logs.read", "process.list", "firewall.list", "system.reboot",
    "user.list", "group.list", "group.remove_user", "storage.list", "storage.extend",
    "firewall.rule.add", "firewall.rule.remove", "firewall.rule.reorder", "network.list", "file.deliver",
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
    completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False, encoding="utf-8", errors="replace")
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
    code, output = run(["/usr/bin/lsblk", "--json", "--bytes", "--output", "NAME,PATH,TYPE,FSTYPE,SIZE,MOUNTPOINTS"])
    try:
        storage = json.loads(output).get("blockdevices", []) if code == 0 else []
    except ValueError:
        storage = []
    logical_volumes: list[dict[str, Any]] = []
    if Path("/usr/sbin/lvs").exists():
        lvs_code, lvs_output = run(["/usr/sbin/lvs", "--reportformat", "json", "--units", "b", "--nosuffix", "--options", "lv_path,vg_name,lv_name,lv_size,data_percent"])
        if lvs_code == 0:
            try:
                logical_volumes = json.loads(lvs_output).get("report", [{}])[0].get("lv", [])
            except (ValueError, IndexError):
                pass
    services_code, services_output = run(["/usr/bin/systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"])
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
        script = "$s=New-Object -ComObject Microsoft.Update.Session;$r=$s.CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0\");$r.Updates.Count"
        code, output = powershell(script, timeout=180)
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
        if code == 0:
            rules = parse_ufw_rules(output)
            capabilities = {"profiles": [], "activeProfiles": [], "zones": [], "defaultZone": "", "targets": []}
            return 0, json.dumps({"backend": "ufw", "backends": ["ufw"], "capabilities": capabilities, "rules": rules}, ensure_ascii=False, separators=(",", ":"))
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
        parts.append("accept" if values["action"] == "allow" else values["action"])
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
        command += [values["protocol"], "dport", str(values["local_port"]), "accept" if values["action"] == "allow" else values["action"], "comment", f"TramOps - {values['name']}"]
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


def execute_job(action: str, parameters: dict[str, Any], inventory: dict[str, Any]) -> tuple[int, str]:
    if action not in ALLOWED_ACTIONS:
        return 126, "Action is not allowlisted by this agent"
    if action == "file.deliver":
        return 126, "File delivery requires the signed agent download channel"
    windows = inventory["os_family"] == "windows"
    if action == "inventory.collect":
        return 0, json.dumps(collect_inventory(), ensure_ascii=False, indent=2)
    if action == "service.list":
        return powershell("Get-Service|Select Name,DisplayName,Status,StartType|ConvertTo-Json -Depth 2") if windows else run(["/usr/bin/systemctl", "list-units", "--type=service", "--all", "--no-pager"])
    if action in {"service.start", "service.stop", "service.restart"}:
        name = require_name(parameters, "name", service=True)
        verb = action.split(".")[1]
        if windows:
            cmdlet = {"start": "Start-Service", "stop": "Stop-Service", "restart": "Restart-Service"}[verb]
            return powershell(f"{cmdlet} -Name '{name}' -ErrorAction Stop; Get-Service -Name '{name}'|Select Name,Status|ConvertTo-Json -Compress")
        return run(["/usr/bin/systemctl", verb, name], timeout=180)
    if action == "group.create":
        group = require_group(parameters)
        if windows:
            return powershell(f"if(-not(Get-LocalGroup -Name '{group}' -ErrorAction SilentlyContinue)){{New-LocalGroup -Name '{group}' -ErrorAction Stop}}")
        return run(["/usr/sbin/groupadd", group])
    if action == "group.delete":
        group = require_group(parameters)
        return powershell(f"Remove-LocalGroup -Name '{group}' -ErrorAction Stop") if windows else run(["/usr/sbin/groupdel", group])
    if action == "user.list":
        facts = management_facts("windows" if windows else "linux")
        return 0, json.dumps(facts.get("Users", []), ensure_ascii=False)
    if action == "group.list":
        facts = management_facts("windows" if windows else "linux")
        return 0, json.dumps(facts.get("Groups", []), ensure_ascii=False)
    if action == "user.create":
        username = require_name(parameters, "username")
        groups = parameters.get("groups", [])
        if not isinstance(groups, list) or any(not GROUP_RE.fullmatch(str(group)) for group in groups):
            raise ValueError("Invalid groups")
        if windows:
            password = str(parameters.get("password", ""))
            if len(password) < 12:
                raise ValueError("Password must have at least 12 characters")
            group_script = ";".join(f"Add-LocalGroupMember -Group '{group}' -Member '{username}' -ErrorAction Stop" for group in groups)
            escaped = password.replace("'", "''")
            return powershell(f"$p=ConvertTo-SecureString '{escaped}' -AsPlainText -Force;New-LocalUser -Name '{username}' -Password $p -PasswordNeverExpires:$false -UserMayNotChangePassword:$false -ErrorAction Stop;{group_script}")
        command = ["/usr/sbin/useradd", "--create-home", "--shell", "/bin/bash"]
        if groups:
            command += ["--groups", ",".join(str(group) for group in groups)]
        command.append(username)
        exit_code, output = run(command)
        if exit_code:
            return exit_code, output
        password = str(parameters.get("password", ""))
        if password:
            if len(password) < 12 or "\n" in password or ":" in password:
                raise ValueError("Password must have at least 12 characters and cannot contain ':'")
            return run_with_input(["/usr/sbin/chpasswd"], f"{username}:{password}\n")
        return 0, output
    if action == "user.disable":
        username = require_name(parameters, "username")
        return powershell(f"Disable-LocalUser -Name '{username}' -ErrorAction Stop") if windows else run(["/usr/sbin/usermod", "--lock", "--expiredate", "1", username])
    if action == "user.enable":
        username = require_name(parameters, "username")
        return powershell(f"Enable-LocalUser -Name '{username}' -ErrorAction Stop") if windows else run(["/usr/sbin/usermod", "--unlock", "--expiredate", "", username])
    if action == "user.delete":
        username = require_name(parameters, "username")
        return powershell(f"Remove-LocalUser -Name '{username}' -ErrorAction Stop") if windows else run(["/usr/sbin/userdel", "--remove", username])
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
        return 0, json.dumps({"pending_updates": pending_updates(inventory)})
    if action == "patch.install_security":
        if windows:
            script = "$s=New-Object -ComObject Microsoft.Update.Session;$q=$s.CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0\");$c=New-Object -ComObject Microsoft.Update.UpdateColl;foreach($u in $q.Updates){if(-not $u.EulaAccepted){$u.AcceptEula()};[void]$c.Add($u)};$d=$s.CreateUpdateDownloader();$d.Updates=$c;[void]$d.Download();$i=$s.CreateUpdateInstaller();$i.Updates=$c;$r=$i.Install();[pscustomobject]@{ResultCode=$r.ResultCode;RebootRequired=$r.RebootRequired;Count=$c.Count}|ConvertTo-Json -Compress"
            return powershell(script, timeout=7200)
        if inventory["distribution_id"] == "ubuntu":
            return run(["/usr/bin/unattended-upgrade", "--verbose"], timeout=7200)
        tool = "/usr/bin/dnf" if Path("/usr/bin/dnf").exists() else "/usr/bin/yum"
        return run([tool, "-y", "update", "--security"], timeout=7200)
    if action == "logs.read":
        limit = min(1000, max(1, int(parameters.get("limit", 200))))
        if windows:
            log_name = str(parameters.get("log", "System"))
            if log_name not in {"System", "Application", "Security"}:
                raise ValueError("Invalid Windows event log")
            return powershell(f"Get-WinEvent -LogName '{log_name}' -MaxEvents {limit}|Select TimeCreated,Id,LevelDisplayName,ProviderName,Message|ConvertTo-Json -Depth 3")
        unit = parameters.get("unit")
        command = ["/usr/bin/journalctl", "--no-pager", "-n", str(limit), "-o", "short-iso"]
        if unit:
            command += ["-u", require_name(parameters, "unit", service=True)]
        return run(command)
    if action == "process.list":
        rows = [{"pid": p.info["pid"], "name": p.info["name"], "username": p.info.get("username"), "cpu": p.info.get("cpu_percent"), "memory": p.info.get("memory_percent")} for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"])]
        return 0, json.dumps(rows[:2000], ensure_ascii=False)
    if action == "firewall.list":
        return windows_firewall_rules() if windows else linux_firewall_rules()
    if action == "firewall.rule.add":
        return add_firewall_rule(parameters, inventory)
    if action == "firewall.rule.remove":
        return remove_firewall_rules(parameters, inventory)
    if action == "firewall.rule.reorder":
        return reorder_firewall_rule(parameters, inventory)
    if action == "storage.list":
        facts = management_facts("windows" if windows else "linux")
        return 0, json.dumps(facts.get("Storage", []), ensure_ascii=False)
    if action == "storage.extend":
        if windows:
            drive = str(parameters.get("drive", "")).upper().rstrip(":")
            if not re.fullmatch(r"[A-Z]", drive):
                raise ValueError("Invalid Windows drive letter")
            return powershell(f"$s=Get-PartitionSupportedSize -DriveLetter '{drive}';Resize-Partition -DriveLetter '{drive}' -Size $s.SizeMax -Confirm:$false -ErrorAction Stop;Get-Volume -DriveLetter '{drive}'|Select DriveLetter,Size,SizeRemaining|ConvertTo-Json -Compress", timeout=1800)
        logical_volume = str(parameters.get("logical_volume", ""))
        size_gb = int(parameters.get("size_gb", 0))
        if not re.fullmatch(r"/dev/(?:mapper/)?[A-Za-z0-9_.+/-]{1,180}", logical_volume) or not 1 <= size_gb <= 10240:
            raise ValueError("Invalid logical volume or extension size")
        return run(["/usr/sbin/lvextend", "--resizefs", "--size", f"+{size_gb}G", logical_volume], timeout=1800)
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
    response = requests.post(config.server_url + "/api/v1/agent-bootstrap/claim", json=payload, verify=config.tls_verify(), timeout=90)
    response.raise_for_status()
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


def loop(config: Config, once: bool = False) -> None:
    if not all(path.exists() for path in [config.cert_file, config.key_file, config.ca_file]):
        raise RuntimeError("Agent is not enrolled")
    last_inventory = 0.0
    inventory = collect_inventory()
    expensive_metrics_pending = False
    backoff = config.interval
    if not once:
        threading.Thread(target=tunnel_control_loop, args=(config,), name="tram-tunnel-control", daemon=True).start()
    while True:
        try:
            ensure_server_ca(config)
            timestamp = time.time()
            send_inventory = timestamp - last_inventory >= config.inventory_interval
            if send_inventory:
                inventory = collect_inventory()
            include_expensive = expensive_metrics_pending and not send_inventory
            payload = {"agent_id": config.agent_id, "agent_version": AGENT_VERSION, "inventory": inventory if send_inventory else None, "metrics": collect_metrics(inventory, include_expensive=include_expensive)}
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
            for job in data.get("jobs", []):
                LOG.info("job %s action=%s", job["id"], job["action"])
                try:
                    if job["action"] == "file.deliver":
                        exit_code, output = deliver_file(config, job.get("parameters", {}), inventory)
                    else:
                        exit_code, output = execute_job(job["action"], job.get("parameters", {}), inventory)
                except Exception as exc:
                    LOG.exception("job failed")
                    exit_code, output = 1, f"{type(exc).__name__}: {exc}"
                post_result(config, job["id"], exit_code, output)
            backoff = config.interval
            if once:
                return
            time.sleep(config.interval)
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
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--once", action="store_true")
    sub.add_parser("service")
    args = parser.parse_args()
    configure_logging(args.log_file)
    config = Config(args.config)
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
    raise SystemExit(main())
