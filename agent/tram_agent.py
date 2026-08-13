from __future__ import annotations

import argparse
import base64
import getpass
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import psutil
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

AGENT_VERSION = "0.2.2"
LOG = logging.getLogger("tram-agent")
NAME_RE = re.compile(r"^[A-Za-z0-9_.@\\-]{1,128}$")
GROUP_RE = re.compile(r"^[A-Za-z0-9_.@ -]{1,128}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,160}$")
ALLOWED_ACTIONS = {
    "inventory.collect", "service.list", "service.restart", "service.start", "service.stop",
    "user.create", "user.disable", "user.enable", "user.delete", "user.password.reset",
    "group.create", "group.delete", "user.add_group", "patch.scan",
    "patch.install_security", "logs.read", "process.list", "firewall.list", "system.reboot",
    "user.list", "group.list", "group.remove_user", "storage.list", "storage.extend",
    "firewall.rule.add", "firewall.rule.remove", "network.list",
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
    return {"hostname": socket.gethostname(), "os_family": os_family, "os_name": os_name, "os_version": os_version, "distribution_id": distribution_id, "architecture": platform.machine(), "agent_version": AGENT_VERSION, "addresses": network_addresses(), "boot_id": boot_id, "ssh_host_key": ssh_host_key(), "extra": {"kernel": platform.release(), "python": platform.python_version(), **management_facts(os_family)}}


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


def execute_job(action: str, parameters: dict[str, Any], inventory: dict[str, Any]) -> tuple[int, str]:
    if action not in ALLOWED_ACTIONS:
        return 126, "Action is not allowlisted by this agent"
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
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, config.agent_id), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Tram Van Hanh Agents")])).sign(key, hashes.SHA256())
    enrollment_payload = {"token": token, "agent_id": config.agent_id, "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(), "inventory": collect_inventory()}
    for attempt in range(30):
        response = requests.post(config.server_url + "/api/v1/enroll", json=enrollment_payload, timeout=60)
        if response.status_code != 503 or attempt == 29:
            response.raise_for_status()
            break
        LOG.warning("control-plane CA is not ready; enrollment retry %s/30", attempt + 1)
        time.sleep(2)
    data = response.json()
    config.key_file.parent.mkdir(parents=True, exist_ok=True)
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


def ensure_server_ca(config: Config) -> None:
    if config.server_ca_file and config.server_ca_file.is_file():
        return
    if not config.server_url:
        raise RuntimeError("server_url is required to retrieve the server CA")
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
    response = requests.post(f"{config.agent_endpoint}/jobs/{job_id}/result", json={"status": "succeeded" if exit_code == 0 else "failed", "exit_code": exit_code, "output": output}, cert=(str(config.cert_file), str(config.key_file)), verify=config.tls_verify(), timeout=60)
    response.raise_for_status()


def loop(config: Config, once: bool = False) -> None:
    if not all(path.exists() for path in [config.cert_file, config.key_file, config.ca_file]):
        raise RuntimeError("Agent is not enrolled")
    last_inventory = 0.0
    inventory = collect_inventory()
    expensive_metrics_pending = False
    backoff = config.interval
    while True:
        try:
            ensure_server_ca(config)
            timestamp = time.time()
            send_inventory = timestamp - last_inventory >= config.inventory_interval
            if send_inventory:
                inventory = collect_inventory()
            include_expensive = expensive_metrics_pending and not send_inventory
            payload = {"agent_id": config.agent_id, "agent_version": AGENT_VERSION, "inventory": inventory if send_inventory else None, "metrics": collect_metrics(inventory, include_expensive=include_expensive)}
            response = requests.post(config.agent_endpoint + "/checkin", json=payload, cert=(str(config.cert_file), str(config.key_file)), verify=config.tls_verify(), timeout=240)
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
            LOG.warning("control plane unavailable: %s; retry in %ss", exc, backoff)
            if once:
                raise
            time.sleep(backoff)
            backoff = min(300, backoff * 2)


def default_config_path() -> str:
    if platform.system().lower() == "windows":
        return str(Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "TramVanHanh/agent.json")
    return "/etc/tram-agent/agent.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Trạm Vận Hành agent")
    parser.add_argument("--config", default=default_config_path())
    parser.add_argument("--log-file")
    sub = parser.add_subparsers(dest="command", required=True)
    enrollment = sub.add_parser("enroll")
    enrollment.add_argument("--server", required=True)
    enrollment.add_argument("--token")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    configure_logging(args.log_file)
    config = Config(args.config)
    if args.command == "enroll":
        config.server_url = args.server.rstrip("/")
        token = args.token or getpass.getpass("Enrollment token: ")
        enroll(config, token)
        return 0
    loop(config, args.once)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
