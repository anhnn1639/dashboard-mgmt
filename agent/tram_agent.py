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

AGENT_VERSION = "0.4.0"
LOG = logging.getLogger("tram-agent")
NAME_RE = re.compile(r"^[A-Za-z0-9_.@\\-]{1,128}$")
GROUP_RE = re.compile(r"^[A-Za-z0-9_.@ -]{1,128}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,160}$")
TRANSFER_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,179}$")
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
    "firewall.rule.add", "firewall.rule.remove", "network.list", "file.deliver",
}


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


def run(command: list[str], timeout: int = 120, check: bool = False, sensitive: bool = False) -> tuple[int, str]:
    if not sensitive:
        LOG.info("exec action: %s", command[0])
    completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False, encoding="utf-8", errors="replace")
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    output = stdout if completed.returncode == 0 else "\n".join(part for part in (stdout, stderr) if part)
    if check and completed.returncode:
        raise RuntimeError(output or f"Command failed: {completed.returncode}")
    return completed.returncode, output[-100_000:]


def run_with_input(command: list[str], input_value: str, timeout: int = 120) -> tuple[int, str]:
    completed = subprocess.run(command, input=input_value, text=True, capture_output=True, timeout=timeout, check=False, encoding="utf-8", errors="replace")
    output = completed.stdout.strip() if completed.returncode == 0 else "\n".join(part for part in (completed.stdout.strip(), completed.stderr.strip()) if part)
    return completed.returncode, output[-100_000:]


def powershell(script: str, timeout: int = 120) -> tuple[int, str]:
    encoded = base64.b64encode(script.encode("utf-16le")).decode()
    return run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded], timeout=timeout, sensitive=True)


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


def ssh_host_key() -> str | None:
    candidates = [Path("/etc/ssh/ssh_host_ed25519_key.pub"), Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "ssh/ssh_host_ed25519_key.pub"]
    for candidate in candidates:
        if candidate.exists():
            parts = candidate.read_text(errors="replace").strip().split()
            if len(parts) >= 2:
                return f"{parts[0]} {parts[1]}"
    return None


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


def firewall_parameters(parameters: dict[str, Any]) -> tuple[str, int, str, str, str]:
    name = require_name(parameters, "name")
    port = int(parameters.get("port", 0))
    protocol = str(parameters.get("protocol", "tcp")).lower()
    action = str(parameters.get("action", "allow")).lower()
    source = str(parameters.get("source", "any")).strip().lower()
    if not 1 <= port <= 65535 or protocol not in {"tcp", "udp"} or action not in {"allow", "deny"}:
        raise ValueError("Invalid firewall rule")
    if source != "any":
        source = str(ipaddress.ip_network(source, strict=False))
    return name, port, protocol, action, source


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
        if windows:
            return powershell("Get-NetFirewallRule -Enabled True|Select -First 1000 DisplayName,Direction,Action,Profile|ConvertTo-Json -Depth 2")
        if inventory["distribution_id"] == "ubuntu" and Path("/usr/sbin/ufw").exists():
            return run(["/usr/sbin/ufw", "status", "verbose"])
        return run(["/usr/bin/firewall-cmd", "--list-all"])
    if action in {"firewall.rule.add", "firewall.rule.remove"}:
        name, port, protocol, rule_action, source = firewall_parameters(parameters)
        if windows:
            escaped_name = name.replace("'", "''")
            remote = "Any" if source == "any" else source
            if action.endswith("add"):
                windows_action = "Allow" if rule_action == "allow" else "Block"
                return powershell(f"New-NetFirewallRule -DisplayName 'TramOps-{escaped_name}' -Direction Inbound -Action {windows_action} -Protocol {protocol.upper()} -LocalPort {port} -RemoteAddress '{remote}' -ErrorAction Stop|Select Name,DisplayName,Enabled,Direction,Action|ConvertTo-Json -Compress")
            return powershell(f"Get-NetFirewallRule -DisplayName 'TramOps-{escaped_name}' -ErrorAction Stop|Remove-NetFirewallRule -ErrorAction Stop")
        if inventory["distribution_id"] != "ubuntu" or not Path("/usr/sbin/ufw").exists():
            return 1, "Structured firewall changes currently require Ubuntu UFW"
        rule = [rule_action]
        if source != "any":
            rule += ["from", source, "to", "any"]
        rule += ["port", str(port), "proto", protocol]
        if action.endswith("remove"):
            rule.insert(0, "delete")
        return run(["/usr/sbin/ufw", "--force", *rule])
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
    install_pinned_server_ca(config, str(payload.get("server_ca_certificate", "")), str(payload.get("server_ca_sha256", "")))
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
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", package_secret) or not re.fullmatch(r"[0-9a-f]{64}", ca_fingerprint):
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
