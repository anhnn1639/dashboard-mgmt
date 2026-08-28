import importlib.util
import base64
import json
import os
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "tram_agent.py"
SPEC = importlib.util.spec_from_file_location("tram_agent", MODULE_PATH)
assert SPEC and SPEC.loader
tram_agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tram_agent)


class AgentSecurityTests(unittest.TestCase):
    def test_common_firewall_rule_auto_detects_supported_operating_system_backends(self):
        common = {"name": "SSH from jump", "direction": "in", "action": "allow", "protocol": "tcp", "local_port": 22, "remote_port": "any", "source": "any", "destination": "any", "family": "ipv4"}
        windows = {"os_family": "windows", "distribution_id": "windows"}
        with patch.object(tram_agent, "add_firewall_rule", return_value=(0, "created")) as add:
            code, output = tram_agent.add_firewall_rule_auto(common, windows)
            self.assertEqual(code, 0)
            resolved = add.call_args.args[0]
            self.assertEqual((resolved["backend"], resolved["profile"]), ("windows", "Any"))
            self.assertEqual(resolved["source"], "0.0.0.0/0")
            self.assertIn("Auto-selected Windows Firewall", output)

        linux_cases = [
            ("ubuntu", {"backend": "ufw", "capabilities": {}}, {"backend": "ufw"}),
            ("ol", {"backend": "firewalld", "capabilities": {"zones": ["public", "internal"], "defaultZone": "public"}}, {"backend": "firewalld", "zone": "public", "family": "ipv4"}),
            ("rhel", {"backend": "iptables", "capabilities": {"targets": [{"direction": "in", "family": "ipv4", "table": "filter", "chain": "INPUT"}]}}, {"backend": "iptables", "family": "ipv4", "table": "filter", "chain": "INPUT"}),
        ]
        for distribution_id, scan, expected in linux_cases:
            with self.subTest(distribution_id=distribution_id), patch.object(tram_agent, "linux_firewall_rules", return_value=(0, json.dumps(scan))), patch.object(tram_agent, "add_firewall_rule", return_value=(0, "created")) as add:
                code, output = tram_agent.add_firewall_rule_auto(common, {"os_family": "linux", "distribution_id": distribution_id})
                self.assertEqual(code, 0)
                resolved = add.call_args.args[0]
                for key, value in expected.items():
                    self.assertEqual(resolved[key], value)
                self.assertIn("Auto-selected", output)

    @unittest.skipUnless(os.name == "nt", "PowerShell parser is available only on Windows")
    def test_generated_windows_storage_and_update_scripts_parse(self):
        scripts = []
        with patch.object(tram_agent, "powershell", side_effect=lambda script, **_: (scripts.append(script) or (0, "{}"))):
            tram_agent.windows_storage_scan()
            tram_agent.windows_partition_after_resize(0, 3)
            tram_agent.scan_updates({"os_family": "windows"})
        parser = "$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(),[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){$errors|ForEach-Object{$_.Message};exit 1}"
        for script in scripts:
            completed = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", parser],
                input=script,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_agent_version_comes_from_the_shared_version_file(self):
        expected = (MODULE_PATH.parent / "VERSION").read_text(encoding="ascii").strip()
        self.assertEqual(tram_agent.AGENT_VERSION, expected)
        wix_source = (MODULE_PATH.parent / "windows" / "Product.wxs").read_text(encoding="utf-8")
        self.assertIn('Version="$(var.AgentVersion)"', wix_source)

    def test_windows_installer_does_not_wait_for_network_enrollment(self):
        wix_source = (MODULE_PATH.parent / "windows" / "Product.wxs").read_text(encoding="utf-8")
        self.assertIn('Wait="no"', wix_source)
        self.assertIn('Id="REINSTALL"', wix_source)
        self.assertIn('Value="ALL"', wix_source)
        self.assertIn('Id="REINSTALLMODE"', wix_source)
        self.assertIn('Value="amusv"', wix_source)
        self.assertIn('Condition="Installed AND NOT (REMOVE ~= &quot;ALL&quot;)"', wix_source)
        agent_source = MODULE_PATH.read_text(encoding="utf-8")
        service_source = agent_source.split("def run_windows_service", 1)[1].split("\ndef main", 1)[0]
        self.assertLess(
            service_source.index("set_status(SERVICE_RUNNING)"),
            service_source.index("bootstrap_from_windows_installer"),
        )

    def test_repository_url_rejects_embedded_credentials_and_query(self):
        self.assertEqual(tram_agent.validated_repository_url("http://repo.internal/ubuntu/"), "http://repo.internal/ubuntu")
        for value in ("ftp://repo.internal/ubuntu", "https://user:secret@repo.internal/ubuntu", "https://repo.internal/ubuntu?token=secret", "https://repo.internal/ubuntu#latest"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, r"HTTP\(S\)"):
                tram_agent.validated_repository_url(value)

    def test_ubuntu_source_switch_preserves_third_party_repositories_and_restores_defaults(self):
        inventory = {"os_family": "linux", "distribution_id": "ubuntu", "os_version": "22.04.5"}
        original = (
            "deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse\n"
            "deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse\n"
            "deb https://download.docker.com/linux/ubuntu jammy stable\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apt_root = root / "apt"
            state_root = root / "state"
            apt_root.mkdir()
            source = apt_root / "sources.list"
            source.write_text(original, encoding="utf-8")

            code, output = tram_agent.configure_ubuntu_update_source(
                {"mode": "custom", "repository_url": "https://repo.internal/ubuntu"},
                inventory,
                apt_root,
                state_root,
            )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["repositoryUrl"], "https://repo.internal/ubuntu")
            changed = source.read_text(encoding="utf-8")
            self.assertIn("# tram-os-default-disabled deb http://archive.ubuntu.com/ubuntu", changed)
            self.assertIn("# tram-os-default-disabled deb http://security.ubuntu.com/ubuntu", changed)
            self.assertIn("deb https://download.docker.com/linux/ubuntu jammy stable", changed)
            managed = apt_root / "sources.list.d" / tram_agent.APT_MANAGED_SOURCE_NAME
            managed_content = managed.read_text(encoding="utf-8")
            self.assertEqual(managed_content.count("URIs: https://repo.internal/ubuntu"), 4)
            for suite in ("jammy", "jammy-updates", "jammy-security", "jammy-backports"):
                self.assertIn(f"Suites: {suite}", managed_content)

            code, output = tram_agent.configure_ubuntu_update_source({"mode": "default"}, inventory, apt_root, state_root)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["mode"], "default")
            self.assertEqual(source.read_text(encoding="utf-8"), original)
            self.assertFalse(managed.exists())

    def test_ubuntu_source_switch_accepts_separate_pulp_distribution_urls(self):
        inventory = {"os_family": "linux", "distribution_id": "ubuntu", "os_version": "24.04.2"}
        mappings = [
            {"id": "noble", "base_url": "http://pulp.internal/pulp/content/ubuntu/24.04/noble/"},
            {"id": "noble-updates", "base_url": "http://pulp.internal/pulp/content/ubuntu/24.04/noble-updates/"},
            {"id": "noble-security", "base_url": "http://pulp.internal/pulp/content/ubuntu/24.04/noble-security/"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apt_root = root / "apt"
            state_root = root / "state"
            apt_root.mkdir()
            (apt_root / "sources.list").write_text(
                "deb http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse\n"
                "deb https://download.docker.com/linux/ubuntu noble stable\n",
                encoding="utf-8",
            )
            code, output = tram_agent.configure_ubuntu_update_source(
                {"mode": "custom", "repositories": mappings}, inventory, apt_root, state_root
            )
            self.assertEqual(code, 0)
            payload = json.loads(output)
            self.assertEqual(payload["repositoryUrl"], "")
            self.assertEqual(payload["repositoryUrls"], {item["id"]: item["base_url"].rstrip("/") for item in mappings})
            managed_content = (apt_root / "sources.list.d" / tram_agent.APT_MANAGED_SOURCE_NAME).read_text(encoding="utf-8")
            for item in mappings:
                self.assertIn(f"URIs: {item['base_url'].rstrip('/')}\nSuites: {item['id']}", managed_content)
            self.assertNotIn("noble-backports", managed_content)
            with self.assertRaisesRegex(ValueError, "Base, Updates and Security"):
                tram_agent.validated_ubuntu_repository_mappings(
                    {"mode": "custom", "repositories": mappings[:2]}, inventory
                )

    def test_ubuntu_deb822_switch_disables_only_official_stanza(self):
        content = (
            "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu\nSuites: noble noble-updates\nComponents: main universe\n\n"
            "Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: noble\nComponents: stable\n"
        )
        changed = tram_agent.disable_ubuntu_default_sources(content, deb822_default_file=True)
        official, docker = changed.split("\n\n")
        self.assertIn("Enabled: no", official)
        self.assertNotIn("Enabled: no", docker)

    def test_oracle_source_switch_preserves_third_party_repo_and_restores_defaults(self):
        inventory = {"os_family": "linux", "distribution_id": "ol", "os_version": "8.10"}
        oracle_source = (
            "[ol8_baseos_latest]\nname=BaseOS\nbaseurl=https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/$basearch/\nenabled=1\ngpgcheck=1\n\n"
            "[ol8_appstream]\nname=AppStream\nbaseurl=https://yum.oracle.com/repo/OracleLinux/OL8/appstream/$basearch/\nenabled=1\ngpgcheck=1\n"
        )
        docker_source = "[docker-ce-stable]\nname=Docker\nbaseurl=https://download.docker.com/linux/centos/$releasever/$basearch/stable\nenabled=1\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository_root = root / "repos"
            state_root = root / "state"
            repository_root.mkdir()
            oracle_file = repository_root / "oracle-linux-ol8.repo"
            docker_file = repository_root / "docker-ce.repo"
            oracle_file.write_text(oracle_source, encoding="utf-8")
            docker_file.write_text(docker_source, encoding="utf-8")

            code, output = tram_agent.configure_oracle_update_source(
                {
                    "mode": "custom",
                    "repositories": [
                        {"id": "ol8_baseos_latest", "base_url": "https://repo.internal/ol8/baseos/$basearch"},
                        {"id": "ol8_appstream", "base_url": "https://repo.internal/ol8/appstream/$basearch"},
                    ],
                },
                inventory,
                repository_root,
                state_root,
            )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["mode"], "custom")
            self.assertIn("enabled=0", oracle_file.read_text(encoding="utf-8"))
            self.assertEqual(docker_file.read_text(encoding="utf-8"), docker_source)
            managed = repository_root / tram_agent.ORACLE_MANAGED_REPOSITORY_NAME
            managed_content = managed.read_text(encoding="utf-8")
            self.assertIn("[tram_ol8_baseos_latest]", managed_content)
            self.assertIn("https://repo.internal/ol8/appstream/$basearch", managed_content)

            code, output = tram_agent.configure_oracle_update_source({"mode": "default"}, inventory, repository_root, state_root)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["mode"], "default")
            self.assertEqual(oracle_file.read_text(encoding="utf-8"), oracle_source)
            self.assertEqual(docker_file.read_text(encoding="utf-8"), docker_source)
            self.assertFalse(managed.exists())

    def test_windows_update_source_writes_wsus_and_internet_policies(self):
        scripts = []
        wsus_environment = json.dumps({"useWUServer": 1, "wsusServer": "http://wsus.internal:8530", "doNotConnectInternet": 1})
        with patch.object(tram_agent, "powershell", side_effect=lambda script, **_: (scripts.append(script) or (0, "{}" if len(scripts) == 1 else wsus_environment))):
            code, output = tram_agent.configure_windows_update_source({"mode": "wsus", "wsus_url": "http://wsus.internal:8530"})
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["mode"], "wsus")
        self.assertIn("WUServer", scripts[0])
        self.assertIn("WUStatusServer", scripts[0])
        self.assertIn("UseWUServer -Type DWord -Value 1", scripts[0])
        self.assertNotIn("wsus.internal", scripts[0])

        scripts = []
        internet_environment = json.dumps({"useWUServer": 0, "wsusServer": "", "doNotConnectInternet": 0})
        with patch.object(tram_agent, "powershell", side_effect=lambda script, **_: (scripts.append(script) or (0, "{}" if len(scripts) == 1 else internet_environment))):
            code, output = tram_agent.configure_windows_update_source({"mode": "internet"})
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["mode"], "internet")
        self.assertIn("UseWUServer -Type DWord -Value 0", scripts[0])
        self.assertIn("Remove-ItemProperty", scripts[0])

    def test_windows_update_source_rejects_an_effective_policy_mismatch(self):
        internet_environment = json.dumps({"useWUServer": 0, "wsusServer": "", "doNotConnectInternet": 0})
        with patch.object(tram_agent, "powershell", side_effect=[(0, "{}"), (0, internet_environment)]):
            code, output = tram_agent.configure_windows_update_source({"mode": "wsus", "wsus_url": "http://wsus.internal:8530"})
        self.assertEqual(code, 1)
        self.assertIn("verification failed", output)

    def test_command_timeout_is_reported_without_crashing_the_agent(self):
        timeout = subprocess.TimeoutExpired(["slow-command"], 7, output="partial output")
        with patch.object(tram_agent.subprocess, "run", side_effect=timeout):
            code, output = tram_agent.run(["slow-command"], timeout=7)
        self.assertEqual(code, 124)
        self.assertIn("timed out after 7 seconds", output)
        self.assertIn("partial output", output)

    def test_bootstrap_http_error_includes_safe_server_detail(self):
        response = tram_agent.requests.Response()
        response.status_code = 500
        response.url = "https://ops.example.com/api/v1/agent-bootstrap/claim"
        response._content = b'{"detail":"Initial server scan could not be queued"}'
        csr = MagicMock()
        csr.public_bytes.return_value = b"test-csr"
        with tempfile.TemporaryDirectory() as directory:
            config = tram_agent.Config(str(Path(directory) / "agent.json"))
            config.server_url = "https://ops.example.com"
            with patch.object(tram_agent, "create_agent_identity", return_value=(MagicMock(), csr)), patch.object(tram_agent, "collect_inventory", return_value={"os_family": "linux"}), patch.object(tram_agent.requests, "post", return_value=response):
                with self.assertRaisesRegex(RuntimeError, r"HTTP 500.*Initial server scan"):
                    tram_agent.bootstrap_enroll(config, "89d17447-bbd7-4f3c-a9a8-6796c9348b1a", "a" * 43)

    def test_bootstrap_unauthorized_error_identifies_package_without_secret(self):
        response = tram_agent.requests.Response()
        response.status_code = 401
        response.url = "https://ops.example.com/api/v1/agent-bootstrap/claim"
        response._content = b'{"detail":"Bootstrap claim is invalid or expired"}'
        package_id = "89d17447-bbd7-4f3c-a9a8-6796c9348b1a"
        package_secret = "a" * 43
        csr = MagicMock()
        csr.public_bytes.return_value = b"test-csr"
        with tempfile.TemporaryDirectory() as directory:
            config = tram_agent.Config(str(Path(directory) / "agent.json"))
            config.server_url = "https://ops.example.com"
            with patch.object(tram_agent, "create_agent_identity", return_value=(MagicMock(), csr)), patch.object(tram_agent, "collect_inventory", return_value={"os_family": "windows"}), patch.object(tram_agent.requests, "post", return_value=response):
                with self.assertRaisesRegex(RuntimeError, rf"HTTP 401.*package_id={package_id}") as raised:
                    tram_agent.bootstrap_enroll(config, package_id, package_secret)
        self.assertNotIn(package_secret, str(raised.exception))

    def test_windows_pending_update_metric_is_cache_only_and_bounded(self):
        calls = []
        with patch.object(tram_agent, "powershell", side_effect=lambda script, **kwargs: (calls.append((script, kwargs)) or (0, "4"))):
            self.assertEqual(tram_agent.pending_updates({"os_family": "windows"}), 4)
        self.assertIn("$q.Online=$false", calls[0][0])
        self.assertEqual(calls[0][1]["timeout"], tram_agent.WINDOWS_UPDATE_METRIC_TIMEOUT_SECONDS)

    def test_linux_service_allows_netlink_for_inventory_and_firewall(self):
        service = (MODULE_PATH.parent / "tram-agent.service").read_text(encoding="utf-8")
        address_families = next(line for line in service.splitlines() if line.startswith("RestrictAddressFamilies="))
        self.assertIn("AF_NETLINK", address_families.split("=", 1)[1].split())

    def test_linux_installer_is_offline_and_uses_the_standalone_binary(self):
        installer = (MODULE_PATH.parent / "install-linux.sh").read_text(encoding="utf-8")
        service = (MODULE_PATH.parent / "tram-agent.service").read_text(encoding="utf-8")
        self.assertNotIn("apt-get", installer)
        self.assertNotIn("dnf install", installer)
        self.assertNotIn("yum install", installer)
        self.assertNotIn("pip install", installer)
        self.assertIn("ubuntu:22.04|ubuntu:24.04", installer)
        self.assertIn("ol:7*|ol:8*|rhel:7*|rhel:8*", installer)
        self.assertIn("linux/x86_64/tram-agent", installer)
        self.assertIn("ExecStart=/opt/tram-agent/tram-agent", service)

    def test_linux_installer_preserves_a_complete_existing_identity(self):
        installer = (MODULE_PATH.parent / "install-linux.sh").read_text(encoding="utf-8")
        for identity_file in ("agent.json", "agent.crt", "agent.key", "agent-ca.crt", "server-ca.crt"):
            self.assertIn(f"/etc/tram-agent/{identity_file}", installer)
        self.assertIn('identity_state="enrolled"', installer)
        self.assertIn('if [ "$identity_state" = "enrolled" ]', installer)
        upgrade_branch = installer.split('if [ "$identity_state" = "enrolled" ]', 1)[1].split("elif", 1)[0]
        self.assertIn("systemctl restart tram-agent.service", upgrade_branch)
        self.assertNotIn("bootstrap --file", upgrade_branch)
        self.assertIn("Existing Agent identity is incomplete", installer)

    def test_system_command_falls_back_to_standard_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            command = Path(directory) / "iptables"
            command.write_text("test", encoding="ascii")
            command.chmod(0o755)
            with patch.object(tram_agent.shutil, "which", return_value=None), patch.object(tram_agent, "SYSTEM_COMMAND_DIRS", (Path(directory),)):
                self.assertEqual(tram_agent.find_system_command("iptables"), str(command))

    def test_tunnel_url_requires_https(self):
        with tempfile.TemporaryDirectory() as directory:
            secure = tram_agent.Config(str(Path(directory) / "agent.json"))
            secure.agent_endpoint = "https://ops.example.com:9443/api/v1/agent"
            self.assertEqual(
                tram_agent.tunnel_url(secure, "control?agent_id=test"),
                "wss://ops.example.com:9443/api/v1/agent/tunnel/control?agent_id=test",
            )
            secure.agent_endpoint = "http://ops.example.com/api/v1/agent"
            with self.assertRaisesRegex(RuntimeError, "HTTPS"):
                tram_agent.tunnel_url(secure, "control")

    def test_ssh_host_key_follows_guacd_libssh2_preference(self):
        with tempfile.TemporaryDirectory() as directory:
            ssh_root = Path(directory)
            ecdsa = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIdGVzdA== host"
            ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3Q= host"
            (ssh_root / "ssh_host_ed25519_key.pub").write_text(ed25519, encoding="ascii")
            (ssh_root / "ssh_host_ecdsa_key.pub").write_text(ecdsa, encoding="ascii")

            self.assertEqual(
                tram_agent.first_ssh_host_key([
                    ssh_root / "ssh_host_ecdsa_key.pub",
                    ssh_root / "ssh_host_ed25519_key.pub",
                ]),
                "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIdGVzdA==",
            )

    def test_ssh_host_key_falls_back_when_ecdsa_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            ssh_root = Path(directory)
            ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3Q= host"
            (ssh_root / "ssh_host_ed25519_key.pub").write_text(ed25519, encoding="ascii")

            self.assertEqual(
                tram_agent.first_ssh_host_key([
                    ssh_root / "ssh_host_ecdsa_key.pub",
                    ssh_root / "ssh_host_ed25519_key.pub",
                ]),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3Q=",
            )

    def test_file_delivery_rejects_traversal_before_network_access(self):
        with tempfile.TemporaryDirectory() as directory:
            config = tram_agent.Config(str(Path(directory) / "agent.json"))
            result, message = tram_agent.deliver_file(
                config,
                {
                    "transfer_id": "89d17447-bbd7-4f3c-a9a8-6796c9348b1a",
                    "filename": "../payload.exe",
                    "sha256": "a" * 64,
                    "size_bytes": 10,
                },
                {"os_family": "linux"},
            )
            self.assertEqual(result, 2)
            self.assertIn("Unsafe", message)

    def test_agent_never_accepts_arbitrary_tunnel_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            config = tram_agent.Config(str(Path(directory) / "agent.json"))
            # Invalid instructions return before creating a local socket.
            tram_agent.tunnel_stream_worker(
                config,
                {
                    "session_id": "89d17447-bbd7-4f3c-a9a8-6796c9348b1a",
                    "protocol": "ssh",
                    "port": 445,
                },
            )
            tram_agent.tunnel_stream_worker(config, {"session_id": "not-a-uuid", "protocol": "ssh", "port": "not-a-port"})

    def test_file_delivery_rejects_windows_device_names(self):
        with tempfile.TemporaryDirectory() as directory:
            config = tram_agent.Config(str(Path(directory) / "agent.json"))
            result, message = tram_agent.deliver_file(
                config,
                {
                    "transfer_id": "89d17447-bbd7-4f3c-a9a8-6796c9348b1a",
                    "filename": "CON.txt",
                    "sha256": "a" * 64,
                    "size_bytes": 10,
                },
                {"os_family": "windows"},
            )
            self.assertEqual(result, 2)
            self.assertIn("Unsafe", message)

    def test_windows_msi_filename_carries_origin_and_ca_pin(self):
        netloc = base64.urlsafe_b64encode(b"ops.company.example").decode().rstrip("=")
        package_id = "89d17447-bbd7-4f3c-a9a8-6796c9348b1a"
        package_secret = "a" * 43
        ca_fingerprint = "b" * 64
        source = f"C:/Downloads/TramAgent--{netloc}--{package_id}--{package_secret}--{ca_fingerprint}.msi"
        self.assertEqual(
            tram_agent.parse_windows_installer_source(source),
            ("https://ops.company.example", package_id, package_secret, ca_fingerprint),
        )
        with self.assertRaisesRegex(RuntimeError, "bootstrap"):
            tram_agent.parse_windows_installer_source("C:/Downloads/renamed.msi")

    def test_windows_msi_can_bootstrap_through_public_nginx_tls(self):
        netloc = base64.urlsafe_b64encode(b"ops.company.example").decode().rstrip("=")
        package_id = "89d17447-bbd7-4f3c-a9a8-6796c9348b1a"
        package_secret = "a" * 43
        source = f"C:/Downloads/TramAgent--{netloc}--{package_id}--{package_secret}--system.msi"
        self.assertEqual(
            tram_agent.parse_windows_installer_source(source),
            ("https://ops.company.example", package_id, package_secret, "system"),
        )

    def test_ufw_numbered_rules_are_normalized_for_exact_deletion(self):
        rules = tram_agent.parse_ufw_rules(
            "Status: active\n\n[ 1] 22/tcp                     ALLOW IN    10.0.0.0/8\n"
            "[ 2] 53/udp                     DENY OUT    Anywhere"
        )
        self.assertEqual([rule["id"] for rule in rules], ["1", "2"])
        self.assertEqual(rules[0]["localPort"], "22")
        self.assertEqual(rules[1]["direction"], "out")
        self.assertTrue(all(rule["reorderable"] for rule in rules))
        self.assertEqual(rules[0]["spec"]["insertArguments"], ["allow", "in", "proto", "tcp", "from", "10.0.0.0/8", "to", "0.0.0.0/0", "port", "22"])

    def test_nftables_rules_use_kernel_handles(self):
        output = '{"nftables":[{"rule":{"family":"inet","table":"filter","chain":"input","handle":17,"comment":"SSH","expr":[{"accept":null}]}}]}'
        rules = tram_agent.parse_nft_rules(output)
        self.assertEqual(rules[0]["id"], "inet:filter:input:17")
        self.assertEqual(rules[0]["spec"]["handle"], 17)
        self.assertEqual(rules[0]["action"], "accept")
        self.assertTrue(rules[0]["reorderable"])

    def test_nftables_add_targets_only_include_live_filter_input_and_output_hooks(self):
        output = json.dumps({"nftables": [
            {"chain": {"family": "inet", "table": "filter", "name": "host_in", "type": "filter", "hook": "input"}},
            {"chain": {"family": "inet", "table": "filter", "name": "host_out", "type": "filter", "hook": "output"}},
            {"chain": {"family": "inet", "table": "filter", "name": "forward", "type": "filter", "hook": "forward"}},
            {"chain": {"family": "ip", "table": "nat", "name": "DOCKER", "type": "nat", "hook": "prerouting"}},
        ]})
        targets = tram_agent.parse_nft_filter_targets(output)
        self.assertEqual([target["chain"] for target in targets], ["host_in", "host_out"])
        self.assertEqual([target["direction"] for target in targets], ["in", "out"])

    def test_nftables_reorder_is_one_json_transaction(self):
        output = '{"nftables":[{"rule":{"family":"inet","table":"filter","chain":"input","handle":17,"expr":[{"drop":null}]}},{"rule":{"family":"inet","table":"filter","chain":"input","handle":21,"comment":"SSH","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},{"accept":null}]}}]}'
        rules = tram_agent.parse_nft_rules(output)
        batches = []
        with patch.object(tram_agent.shutil, "which", return_value="/usr/sbin/nft"), patch.object(tram_agent, "run", return_value=(0, output)), patch.object(tram_agent, "run_with_input", side_effect=lambda command, value: (batches.append(json.loads(value)) or (0, "ok"))):
            code, _ = tram_agent.reorder_nftables_rule({"rule": rules[1], "before": rules[0]})
        self.assertEqual(code, 0)
        commands = batches[0]["nftables"]
        self.assertEqual(commands[0]["insert"]["rule"]["handle"], 17)
        self.assertEqual(commands[1]["delete"]["rule"]["handle"], 21)

    def test_empty_nftables_ruleset_is_a_successful_scan(self):
        def fake_which(name):
            return "/usr/sbin/nft" if name == "nft" else None

        with patch.object(tram_agent.shutil, "which", side_effect=fake_which), patch.object(tram_agent, "run", return_value=(0, '{"nftables":[{"metainfo":{"json_schema_version":1}}]}')):
            code, output = tram_agent.linux_firewall_rules()
        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(payload["backend"], "nftables")
        self.assertEqual(payload["rules"], [])

    def test_missing_firewall_backend_is_reported_without_failing_the_job(self):
        with patch.object(tram_agent.shutil, "which", return_value=None), patch.object(tram_agent, "SYSTEM_COMMAND_DIRS", ()):
            code, output = tram_agent.linux_firewall_rules()
        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(payload["backend"], "")
        self.assertIn("No active or supported firewall backend", payload["warning"])
        self.assertIn("ipv4: iptables not found", payload["warning"])

    def test_firewalld_scans_services_ports_and_ipv6_rich_rules(self):
        output = """public (active)
  services: cockpit ssh
  ports: 8443/tcp
  rich rules:
    rule family=\"ipv6\" source address=\"2001:db8::/64\" port port=\"443\" protocol=\"tcp\" accept
"""
        rules = tram_agent.parse_firewalld_rules(output)
        self.assertEqual(len(rules), 4)
        self.assertEqual(rules[-1]["source"], "2001:db8::/64")
        self.assertEqual(rules[-1]["localPort"], "443")
        self.assertEqual(rules[-1]["spec"]["zone"], "public")

    def test_firewalld_capabilities_include_empty_zones_from_the_server(self):
        output = """block
  services:
public (active)
  services: cockpit ssh
trusted
  services:
"""
        self.assertEqual(tram_agent.parse_firewalld_zones(output), ["block", "public", "trusted"])

    def test_iptables_rules_keep_per_chain_line_numbers(self):
        output = "*filter\n-A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -m comment --comment SSH -j ACCEPT\n-A INPUT -p udp --dport 53 -j DROP\nCOMMIT"
        rules = tram_agent.parse_iptables_rules(output, "ipv4")
        self.assertEqual([rule["spec"]["index"] for rule in rules], [1, 2])
        self.assertEqual(rules[0]["source"], "10.0.0.0/8")
        self.assertEqual(rules[1]["action"], "drop")

    def test_iptables_command_is_used_when_save_helper_is_missing(self):
        def fake_which(name):
            return "/usr/sbin/iptables" if name == "iptables" else None

        def fake_run(command, *args, **kwargs):
            table = command[command.index("-t") + 1]
            if table == "filter":
                return 0, "-P INPUT ACCEPT\n-A INPUT -s 10.64.83.172/32 -p tcp --dport 22 -j ACCEPT\n-A FORWARD -j DOCKER-USER"
            return 1, f"Table {table} does not exist"

        with patch.object(tram_agent, "find_system_command", side_effect=fake_which), patch.object(tram_agent, "run", side_effect=fake_run):
            code, output = tram_agent.linux_firewall_rules()
        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(payload["backend"], "iptables")
        self.assertEqual(payload["families"], ["ipv4"])
        self.assertEqual(payload["rules"][0]["source"], "10.64.83.172/32")
        self.assertTrue(payload["rules"][0]["removable"])
        self.assertFalse(payload["rules"][1]["removable"])
        self.assertEqual(payload["rules"][1]["managedBy"], "docker")
        self.assertEqual(
            [(target["chain"], target["direction"]) for target in payload["capabilities"]["targets"]],
            [("INPUT", "in")],
        )

    def test_iptables_add_rejects_a_chain_that_disappeared_after_scan(self):
        parameters = {
            "backend": "iptables", "name": "Web nội bộ", "direction": "in",
            "action": "allow", "protocol": "tcp", "local_port": 443,
            "source": "10.0.0.0/8", "destination": "any", "family": "ipv4",
            "table": "filter", "chain": "MISSING",
        }
        with patch.object(tram_agent, "find_system_command", return_value="/usr/sbin/iptables"), patch.object(
            tram_agent, "run", return_value=(0, "-P INPUT ACCEPT\n-P OUTPUT ACCEPT")
        ):
            with self.assertRaisesRegex(ValueError, "no longer available"):
                tram_agent.add_firewall_rule(parameters, {"os_family": "linux"})

    def test_iptables_add_rejects_an_address_from_the_wrong_family(self):
        parameters = {
            "backend": "iptables", "name": "Web IPv6", "direction": "in",
            "action": "allow", "protocol": "tcp", "local_port": 443,
            "source": "2001:db8::/64", "destination": "any", "family": "ipv4",
            "table": "filter", "chain": "INPUT",
        }
        with patch.object(tram_agent, "find_system_command", return_value="/usr/sbin/iptables"), patch.object(
            tram_agent, "run", return_value=(0, "-P INPUT ACCEPT\n-P OUTPUT ACCEPT")
        ):
            with self.assertRaisesRegex(ValueError, "does not match"):
                tram_agent.add_firewall_rule(parameters, {"os_family": "linux"})

    def test_new_ordered_firewall_rules_are_inserted_first(self):
        common = {
            "name": "SSH từ jump", "direction": "in", "action": "allow",
            "protocol": "tcp", "local_port": 22, "source": "10.11.12.10/32",
            "destination": "any",
        }

        ufw_commands = []
        with patch.object(tram_agent, "find_system_command", return_value="/usr/sbin/ufw"), patch.object(
            tram_agent, "run", side_effect=lambda command, **_: (ufw_commands.append(command) or (0, "ok"))
        ):
            tram_agent.add_firewall_rule({**common, "backend": "ufw"}, {"os_family": "linux"})
        self.assertEqual(ufw_commands[0][:5], ["/usr/sbin/ufw", "--force", "insert", "1", "allow"])

        nft_commands = []
        nft_ruleset = json.dumps({"nftables": [{"chain": {"family": "inet", "table": "filter", "name": "input", "type": "filter", "hook": "input"}}]})
        def nft_run(command, **_):
            nft_commands.append(command)
            return (0, nft_ruleset) if "list" in command else (0, "ok")
        with patch.object(tram_agent, "find_system_command", return_value="/usr/sbin/nft"), patch.object(tram_agent, "run", side_effect=nft_run):
            tram_agent.add_firewall_rule({**common, "backend": "nftables", "family": "inet", "table": "filter", "chain": "input"}, {"os_family": "linux"})
        self.assertEqual(nft_commands[-1][:6], ["/usr/sbin/nft", "insert", "rule", "inet", "filter", "input"])

        iptables_commands = []
        def iptables_run(command, **_):
            iptables_commands.append(command)
            return (0, "-P INPUT ACCEPT\n-P OUTPUT ACCEPT") if "-S" in command else (0, "ok")
        with patch.object(tram_agent, "find_system_command", return_value="/usr/sbin/iptables"), patch.object(tram_agent, "run", side_effect=iptables_run):
            tram_agent.add_firewall_rule({**common, "backend": "iptables", "family": "ipv4", "table": "filter", "chain": "INPUT"}, {"os_family": "linux"})
        self.assertEqual(iptables_commands[-1][:8], ["/usr/sbin/iptables", "-w", "-t", "filter", "-I", "INPUT", "1", "-p"])

    def test_common_deny_action_maps_to_native_drop_verdicts(self):
        common = {"name": "Block test", "direction": "in", "action": "deny", "protocol": "tcp", "local_port": 22, "source": "10.0.0.0/8", "destination": "any"}
        nft_commands = []
        nft_ruleset = json.dumps({"nftables": [{"chain": {"family": "inet", "table": "filter", "name": "input", "type": "filter", "hook": "input"}}]})

        def nft_run(command, **_):
            nft_commands.append(command)
            return (0, nft_ruleset) if "list" in command else (0, "ok")

        with patch.object(tram_agent, "find_system_command", return_value="/usr/sbin/nft"), patch.object(tram_agent, "run", side_effect=nft_run):
            tram_agent.add_firewall_rule({**common, "backend": "nftables", "family": "inet", "table": "filter", "chain": "input"}, {"os_family": "linux"})
        self.assertIn("drop", nft_commands[-1])
        self.assertNotIn("deny", nft_commands[-1])

        firewalld_commands = []

        def firewalld_run(command, **_):
            firewalld_commands.append(command)
            return (0, "public internal") if "--get-zones" in command else (0, "ok")

        with patch.object(tram_agent, "find_system_command", return_value="/usr/bin/firewall-cmd"), patch.object(tram_agent, "run", side_effect=firewalld_run):
            tram_agent.add_firewall_rule({**common, "backend": "firewalld", "zone": "public", "family": "ipv4"}, {"os_family": "linux"})
        rich_arguments = [part for command in firewalld_commands for part in command if part.startswith("--add-rich-rule=")]
        self.assertTrue(rich_arguments)
        self.assertTrue(all(argument.endswith(" drop") and " deny" not in argument for argument in rich_arguments))

    def test_nftables_comment_is_one_quoted_and_escaped_literal(self):
        commands = []
        ruleset = json.dumps({"nftables": [{"chain": {"family": "ip", "table": "filter", "name": "INPUT", "type": "filter", "hook": "input"}}]})

        def fake_run(command, **_):
            commands.append(command)
            return (0, ruleset) if "list" in command else (0, "ok")

        parameters = {
            "backend": "nftables", "name": 'SSH "jump" \\ ops', "direction": "in",
            "action": "allow", "protocol": "tcp", "local_port": 22,
            "source": "10.64.83.172/32", "destination": "any",
            "family": "ip", "table": "filter", "chain": "INPUT",
        }
        with patch.object(tram_agent, "find_system_command", return_value="/usr/sbin/nft"), patch.object(tram_agent, "run", side_effect=fake_run):
            tram_agent.add_firewall_rule(parameters, {"os_family": "linux"})

        command = commands[-1]
        self.assertEqual(command[-2], "comment")
        self.assertEqual(json.loads(command[-1]), 'TramOps - SSH "jump" \\ ops')
        self.assertTrue(command[-1].startswith('"') and command[-1].endswith('"'))

    def test_docker_managed_iptables_rule_cannot_be_deleted(self):
        output = "-A FORWARD -j DOCKER-USER"
        rule = tram_agent.parse_iptables_rules(f"*filter\n{output}\nCOMMIT", "ipv4")[0]

        def fake_which(name):
            return "/usr/sbin/iptables" if name == "iptables" else None

        with patch.object(tram_agent.shutil, "which", side_effect=fake_which), patch.object(tram_agent, "run", return_value=(0, output)):
            with self.assertRaisesRegex(ValueError, "Docker-managed"):
                tram_agent.remove_firewall_rules({"rules": [rule]}, {"os_family": "linux"})

    def test_ufw_bulk_delete_runs_descending_to_avoid_renumbering(self):
        commands = []

        def fake_run(command, *args, **kwargs):
            commands.append(command)
            return 0, "ok"

        with patch.object(tram_agent.shutil, "which", return_value="/usr/sbin/ufw"), patch.object(tram_agent, "run", side_effect=fake_run):
            code, _ = tram_agent.remove_firewall_rules(
                {"rules": [
                    {"backend": "ufw", "id": "2", "spec": {"number": 2}},
                    {"backend": "ufw", "id": "7", "spec": {"number": 7}},
                ]},
                {"os_family": "linux"},
            )
        self.assertEqual(code, 0)
        self.assertEqual([command[-1] for command in commands], ["7", "2"])

    def test_ufw_reorder_inserts_clone_then_deletes_original_with_stale_guard(self):
        output = "Status: active\n\n[ 1] 22/tcp                     DENY IN     Anywhere\n[ 2] 22/tcp                     ALLOW IN    10.0.0.0/8"
        rules = tram_agent.parse_ufw_rules(output)
        commands = []

        def fake_run(command, *args, **kwargs):
            commands.append(command)
            return (0, output) if command[-2:] == ["status", "numbered"] else (0, "ok")

        with patch.object(tram_agent.shutil, "which", return_value="/usr/sbin/ufw"), patch.object(tram_agent, "run", side_effect=fake_run):
            code, _ = tram_agent.reorder_ufw_rule({"rule": rules[1], "before": rules[0]})
        self.assertEqual(code, 0)
        self.assertEqual(commands[1][:5], ["/usr/sbin/ufw", "--force", "insert", "1", "allow"])
        self.assertEqual(commands[2], ["/usr/sbin/ufw", "--force", "delete", "3"])
        stale = {**rules[1], "raw": rules[1]["raw"] + " changed"}
        commands.clear()
        with patch.object(tram_agent.shutil, "which", return_value="/usr/sbin/ufw"), patch.object(tram_agent, "run", side_effect=fake_run):
            with self.assertRaisesRegex(ValueError, "changed after the scan"):
                tram_agent.reorder_ufw_rule({"rule": stale, "before": rules[0]})
        self.assertEqual(len(commands), 1)

    def test_iptables_reorder_restores_the_same_chain_in_requested_order(self):
        output = "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 22 -j DROP\n-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT\nCOMMIT"
        rules = tram_agent.parse_iptables_rules(output, "ipv4")
        restored = []

        def fake_which(name):
            return f"/usr/sbin/{name}"

        with patch.object(tram_agent.shutil, "which", side_effect=fake_which), patch.object(tram_agent, "run", return_value=(0, output)), patch.object(tram_agent, "run_with_input", side_effect=lambda command, value: (restored.append(value) or (0, "ok"))):
            code, _ = tram_agent.reorder_iptables_rule({"rule": rules[1], "before": rules[0]})
        self.assertEqual(code, 0)
        self.assertIn("-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT\n-A INPUT -p tcp --dport 22 -j DROP", restored[0])

    def test_iptables_reorder_uses_native_commands_without_save_restore(self):
        output = "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j DROP\n-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT"
        rules = tram_agent.parse_iptables_rules(f"*filter\n{output}\nCOMMIT", "ipv4")
        commands = []

        def fake_which(name):
            return "/usr/sbin/iptables" if name == "iptables" else None

        def fake_run(command, *args, **kwargs):
            commands.append(command)
            return (0, output) if command[-2:] == ["-S", "INPUT"] else (0, "ok")

        with patch.object(tram_agent, "find_system_command", side_effect=fake_which), patch.object(tram_agent, "run", side_effect=fake_run):
            code, _ = tram_agent.reorder_iptables_rule({"rule": rules[1], "before": rules[0]})
        self.assertEqual(code, 0)
        self.assertEqual(commands[1][:8], ["/usr/sbin/iptables", "-w", "-t", "filter", "-I", "INPUT", "1", "-p"])
        self.assertEqual(commands[2], ["/usr/sbin/iptables", "-w", "-t", "filter", "-D", "INPUT", "3"])

    def test_firewall_object_names_cannot_inject_commands(self):
        with patch.object(tram_agent.shutil, "which", return_value="/usr/sbin/nft"):
            with self.assertRaisesRegex(ValueError, "nftables target"):
                tram_agent.add_firewall_rule(
                    {"backend": "nftables", "name": "Web nội bộ", "direction": "in", "action": "allow", "protocol": "tcp", "local_port": 443, "source": "any", "destination": "any", "family": "inet", "table": "filter;reboot", "chain": "input"},
                    {"os_family": "linux"},
                )

    def test_parted_free_regions_are_reported_in_bytes(self):
        output = "BYT;\n/dev/sda:107374182400B:scsi:512:4096:gpt:Disk;\n:1048576B:1073741823B:1072693248B:free;\n1:1073741824B:53687091199B:52613349376B:ext4:root:;\n:53687091200B:107373133823B:53686042624B:free;"
        with patch.object(tram_agent, "find_system_command", return_value="/usr/sbin/parted"), patch.object(tram_agent, "run", return_value=(0, output)):
            regions = tram_agent.parted_free_regions("/dev/sda")
        self.assertEqual(len(regions), 2)
        self.assertEqual(regions[-1]["startBytes"], 53687091200)
        self.assertEqual(regions[-1]["sizeBytes"], 53686042624)
        with patch.object(tram_agent, "find_system_command", return_value="/usr/sbin/parted"), patch.object(tram_agent, "run", return_value=(0, output)):
            layout = tram_agent.parted_disk_layout("/dev/sda")
        self.assertEqual(layout["partitionTable"], "gpt")
        self.assertEqual(layout["partitions"][1]["startBytes"], 1073741824)

    def test_oracle_linux_7_storage_falls_back_to_lsblk_pairs(self):
        pairs = '\n'.join([
            'NAME="sda" KNAME="sda" PKNAME="" TYPE="disk" FSTYPE="" LABEL="" UUID="" SIZE="107374182400" MOUNTPOINT="" MODEL="Virtual Disk" RO="0" RM="0" PTTYPE=""',
            'NAME="sda2" KNAME="sda2" PKNAME="sda" TYPE="part" FSTYPE="LVM2_member" LABEL="" UUID="pv" SIZE="106030956544" MOUNTPOINT="" MODEL="" RO="0" RM="0" PTTYPE=""',
            'NAME="sda1" KNAME="sda1" PKNAME="sda" TYPE="part" FSTYPE="xfs" LABEL="boot" UUID="abc" SIZE="1073741824" MOUNTPOINT="/boot" MODEL="" RO="0" RM="0" PTTYPE=""',
            'NAME="dm-0" KNAME="dm-0" PKNAME="" TYPE="lvm" FSTYPE="xfs" LABEL="root" UUID="lv" SIZE="100000000000" MOUNTPOINT="/" MODEL="" RO="0" RM="0" PTTYPE=""',
        ])
        parted = "BYT;\n/dev/sda:107374182400B:scsi:512:4096:gpt:Disk;\n1:1048576B:1074790399B:1073741824B:xfs:boot:boot;\n2:1074790400B:107105746943B:106030956544B:::lvm;\n:107105746944B:107374182399B:268435456B:free;"
        def fake_run(command, **_kwargs):
            if "--json" in command:
                return 1, "/usr/bin/lsblk: unrecognized option '--json'"
            if "--pairs" in command:
                return 0, pairs
            if command[0] == "/usr/sbin/parted":
                return 0, parted
            return 0, ""
        with patch.object(tram_agent, "find_system_command", side_effect=lambda name: {"lsblk": "/usr/bin/lsblk", "parted": "/usr/sbin/parted"}.get(name)), patch.object(tram_agent, "run", side_effect=fake_run):
            code, output = tram_agent.linux_storage_scan()
        self.assertEqual(code, 0)
        parsed = json.loads(output)
        self.assertEqual(len(parsed["disks"]), 1)
        self.assertEqual(parsed["disks"][0]["path"], "/dev/sda")
        self.assertEqual(parsed["disks"][0]["partitionTable"], "gpt")
        self.assertEqual(parsed["disks"][0]["children"][0]["path"], "/dev/sda1")
        self.assertEqual(parsed["disks"][0]["children"][0]["mountpoints"], ["/boot"])
        self.assertTrue(parsed["disks"][0]["children"][0]["resizeProtected"])
        self.assertEqual(parsed["disks"][0]["children"][1]["path"], "/dev/sda2")
        self.assertEqual(parsed["disks"][0]["children"][1]["partitionNumber"], 2)
        self.assertEqual(parsed["disks"][0]["children"][1]["extendableBytes"], 268435456)

    def test_windows_storage_scan_reports_ordered_free_segments_and_resize_limits(self):
        scripts = []
        with patch.object(tram_agent, "powershell", side_effect=lambda script, **_: (scripts.append(script) or (0, '{"disks":[]}'))):
            code, _ = tram_agent.windows_storage_scan()
        self.assertEqual(code, 0)
        self.assertIn("Sort-Object Offset", scripts[0])
        self.assertIn("type='unallocated'", scripts[0])
        self.assertIn("offsetBytes", scripts[0])
        self.assertIn("endOffsetBytes=([int64]$p.Offset+[int64]$p.Size)", scripts[0])
        self.assertIn("shrinkableBytes", scripts[0])
        self.assertIn("shrinkSupported", scripts[0])
        self.assertIn("adjacentUnallocatedBytes", scripts[0])
        self.assertIn("$part.extendableBytes=[int64]$next.sizeBytes", scripts[0])
        self.assertIn("sizeQuerySucceeded", scripts[0])
        self.assertIn("largestFreeExtentBytes", scripts[0])
        self.assertIn("system|reserved|recovery|oem|unknown", scripts[0])

    def test_windows_shrink_uses_diskpart_and_verifies_the_result(self):
        scan = {"disks": [{"number": 0, "partitions": [{"partitionNumber": 3, "driveLetter": "C", "filesystem": "NTFS", "sizeBytes": 20 * 1024**3, "shrinkSupported": True, "resizeProtected": False}]}]}
        diskpart_inputs = []
        after = json.dumps({"diskNumber": 0, "partitionNumber": 3, "driveLetter": "C", "sizeBytes": 19 * 1024**3})
        with patch.object(tram_agent, "parsed_storage_scan", return_value=scan), patch.object(tram_agent, "run_with_input", side_effect=lambda command, input_value, **_: (diskpart_inputs.append((command, input_value)) or (0, "DiskPart succeeded"))), patch.object(tram_agent, "powershell", return_value=(0, after)):
            code, _ = tram_agent.shrink_storage(
                {"kind": "windows_partition", "disk_number": 0, "partition_number": 3, "shrink_bytes": 1024**3},
                True,
            )
        self.assertEqual(code, 0)
        self.assertEqual(diskpart_inputs[0][0], ["diskpart.exe"])
        self.assertIn("select volume C", diskpart_inputs[0][1])
        self.assertIn("shrink desired=1024 minimum=1024", diskpart_inputs[0][1])
        with self.assertRaisesRegex(ValueError, "Windows NTFS"):
            tram_agent.shrink_storage(
                {"kind": "windows_partition", "disk_number": 0, "partition_number": 3, "shrink_bytes": 1024**3},
                False,
            )

    def test_windows_extend_uses_the_immediately_adjacent_extent(self):
        scan = {"disks": [{"number": 0, "partitions": [{"partitionNumber": 3, "driveLetter": "C", "filesystem": "NTFS", "sizeBytes": 90 * 1024**3, "extendableBytes": 10 * 1024**3, "adjacentUnallocatedBytes": 10 * 1024**3, "resizeProtected": False}]}]}
        diskpart_inputs = []
        after = json.dumps({"diskNumber": 0, "partitionNumber": 3, "driveLetter": "C", "sizeBytes": 100 * 1024**3})
        with patch.object(tram_agent, "parsed_storage_scan", return_value=scan), patch.object(tram_agent, "run_with_input", side_effect=lambda command, input_value, **_: (diskpart_inputs.append(input_value) or (0, "DiskPart succeeded"))), patch.object(tram_agent, "powershell", return_value=(0, after)):
            code, output = tram_agent.extend_storage({"kind": "windows_partition", "disk_number": 0, "partition_number": 3, "add_bytes": 10 * 1024**3}, True)
        self.assertEqual(code, 0, output)
        self.assertIn("select volume C", diskpart_inputs[0])
        self.assertIn("extend size=10240", diskpart_inputs[0])

    def test_linux_lv_extend_aligns_decimal_gib_sizes_to_512_bytes(self):
        scan = {
            "logicalVolumes": [
                {"path": "/dev/ol/u01", "extendableBytes": 7_516_160},
                {"path": "/dev/ubuntu-vg/ubuntu-lv", "extendableBytes": 85_899_264},
            ]
        }
        commands = []
        with patch.object(tram_agent, "parsed_storage_scan", return_value=scan), patch.object(tram_agent, "find_system_command", return_value="/usr/sbin/lvextend"), patch.object(tram_agent, "run", side_effect=lambda command, **_: (commands.append(command) or (0, "ok"))):
            oracle_code, _ = tram_agent.extend_storage(
                {"kind": "linux_lv", "path": "/dev/ol/u01", "add_bytes": 7_516_192},
                False,
            )
            ubuntu_code, _ = tram_agent.extend_storage(
                {"kind": "linux_lv", "path": "/dev/ubuntu-vg/ubuntu-lv", "add_bytes": 85_899_345},
                False,
            )
        self.assertEqual(oracle_code, 0)
        self.assertEqual(ubuntu_code, 0)
        self.assertEqual(commands[0], ["/usr/sbin/lvextend", "--resizefs", "--size", "+7516160B", "/dev/ol/u01"])
        self.assertEqual(commands[1], ["/usr/sbin/lvextend", "--resizefs", "--size", "+85899264B", "/dev/ubuntu-vg/ubuntu-lv"])

    def test_powershell_clixml_errors_are_readable(self):
        raw = '#< CLIXML\n<Objs><S S="Error">Exception from HRESULT: 0x80072EE2_x000D__x000A_At line:1 char:1</S></Objs>'
        cleaned = tram_agent.clean_powershell_output(raw)
        self.assertEqual(cleaned, "Exception from HRESULT: 0x80072EE2 At line:1 char:1")
        self.assertNotIn("CLIXML", cleaned)

    def test_update_install_uses_only_selected_apt_packages(self):
        scan = json.dumps({"platform": "linux", "manager": "apt", "updates": [
            {"id": "openssl", "name": "openssl", "version": "3.0.2-1", "repository": "security"},
            {"id": "curl", "name": "curl", "version": "8.0.1-1", "repository": "updates"},
        ]})
        commands = []
        with patch.object(tram_agent, "scan_updates", return_value=(0, scan)), patch.object(tram_agent, "find_system_command", return_value="/usr/bin/apt-get"), patch.object(tram_agent, "run", side_effect=lambda command, **_: (commands.append(command) or (0, "ok"))):
            code, _ = tram_agent.install_updates({"updates": [{"id": "openssl", "version": "3.0.2-1"}]}, {"os_family": "linux", "distribution_id": "ubuntu"})
        self.assertEqual(code, 0)
        self.assertEqual(commands, [["/usr/bin/apt-get", "-y", "--only-upgrade", "install", "openssl=3.0.2-1"]])

    def test_windows_update_scan_indexes_the_com_collection(self):
        calls = []
        def fake_powershell(script, **kwargs):
            calls.append((script, kwargs))
            if "CCM_SoftwareUpdate" in script:
                return 0, "[]"
            if "Microsoft.Update.AutoUpdate" in script:
                return 0, ""
            return 0, '{"platform":"windows","manager":"wua","updates":[],"diagnostics":{"currentScanComplete":true}}'
        environment = {"sourceMode": "windows_update", "sourceLabel": "Windows Update", "policyIssue": "", "lastSearchSuccessDate": ""}
        with patch.object(tram_agent, "windows_update_environment", return_value=environment), \
             patch.object(tram_agent, "windows_update_source_probe", return_value={"reachable": True, "status": "reachable", "endpoint": "https://sls.update.microsoft.com/", "error": ""}), \
             patch.object(tram_agent, "powershell", side_effect=fake_powershell):
            code, _ = tram_agent.scan_updates({"os_family": "windows"})
        scripts = [call[0] for call in calls]
        self.assertEqual(code, 0)
        cached = next((call for call in calls if "$searcher.Online=$false" in call[0]), None)
        online = next((call for call in calls if "$searcher.Online=$true" in call[0]), None)
        self.assertIsNotNone(cached)
        self.assertIsNotNone(online)
        self.assertEqual(cached[1]["timeout"], 60)
        self.assertEqual(online[1]["timeout"], tram_agent.WINDOWS_UPDATE_SCAN_TIMEOUT_SECONDS)
        self.assertIn("$ProgressPreference='SilentlyContinue'", cached[0])
        self.assertIn("$searcher.ServerSelection=2", cached[0])
        self.assertIn('Search("IsInstalled=0 and IsHidden=0")', cached[0])
        self.assertIn("$result.Updates.Item($i)", cached[0])
        self.assertIn("Microsoft.Update.ServiceManager", cached[0])
        self.assertIn("$services.Item($serviceIndex)", cached[0])
        self.assertIn("catch{$queryError=$_.Exception.Message}", cached[0])
        self.assertIn("Microsoft.Update.AutoUpdate", "\n".join(scripts))
        self.assertLess(scripts.index(cached[0]), scripts.index(online[0]))
        configmgr = next(script for script in scripts if "CCM_SoftwareUpdate" in script)
        self.assertIn("root\\ccm\\ClientSDK", configmgr)
        self.assertNotIn("foreach($u in $r.Updates)", configmgr)

    def test_windows_update_environment_detects_incomplete_wsus_policy(self):
        payload = json.dumps({
            "useWUServer": None,
            "wsusServer": "http://wsus.example.test:8530",
            "doNotConnectInternet": 1,
            "registeredServices": [],
        })
        with patch.object(tram_agent, "powershell", return_value=(0, payload)):
            environment = tram_agent.windows_update_environment()
        self.assertEqual(environment["sourceMode"], "invalid_policy")
        self.assertIn("UseWUServer=1", environment["policyIssue"])
        self.assertEqual(environment["wsusServer"], "http://wsus.example.test:8530")

    def test_windows_update_scan_skips_online_query_for_invalid_policy(self):
        environment = {
            "sourceMode": "invalid_policy",
            "sourceLabel": "Windows policy",
            "policyIssue": "Apply a complete WSUS policy before scanning again.",
            "lastSearchSuccessDate": "",
        }
        cached = json.dumps({"platform": "windows", "updates": [], "diagnostics": {"currentScanComplete": False}})
        queries = []
        with patch.object(tram_agent, "windows_update_environment", return_value=environment), \
             patch.object(tram_agent, "windows_configmgr_updates", return_value=[]), \
             patch.object(tram_agent, "windows_update_query", side_effect=lambda **kwargs: (queries.append(kwargs) or (0, cached))):
            code, output = tram_agent.scan_windows_updates()
        parsed = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(queries, [{"online": False, "timeout": 60, "source_mode": "default"}])
        self.assertFalse(parsed["diagnostics"]["currentScanComplete"])
        self.assertEqual(parsed["diagnostics"]["wuaStatus"], "skipped_invalid_policy")

    def test_windows_update_scan_stops_immediately_when_the_source_is_unreachable(self):
        cached = json.dumps({"platform": "windows", "updates": [], "diagnostics": {"currentScanComplete": False}})
        for source_mode, status in (("windows_update", "no_internet"), ("wsus", "wsus_unreachable")):
            with self.subTest(source_mode=source_mode):
                environment = {
                    "sourceMode": source_mode,
                    "sourceLabel": "WSUS" if source_mode == "wsus" else "Windows Update",
                    "wsusServer": "http://wsus.example.test:8530" if source_mode == "wsus" else "",
                    "policyIssue": "",
                    "lastSearchSuccessDate": "",
                }
                queries = []
                with patch.object(tram_agent, "windows_update_environment", return_value=environment), \
                     patch.object(tram_agent, "windows_configmgr_updates", return_value=[]), \
                     patch.object(tram_agent, "windows_update_source_probe", return_value={"reachable": False, "status": status, "endpoint": "", "error": "offline"}), \
                     patch.object(tram_agent, "windows_update_query", side_effect=lambda **kwargs: (queries.append(kwargs) or (0, cached))):
                    code, output = tram_agent.scan_windows_updates()
                parsed = json.loads(output)
                self.assertEqual(code, 0)
                self.assertEqual(queries, [{"online": False, "timeout": 60, "source_mode": source_mode}])
                self.assertEqual(parsed["diagnostics"]["wuaStatus"], status)
                self.assertEqual(parsed["diagnostics"]["connectivityStatus"], status)
                self.assertFalse(parsed["diagnostics"]["currentScanComplete"])

    def test_windows_update_source_probe_uses_bounded_native_endpoints_and_proxy(self):
        scripts = []
        response = json.dumps({"reachable": True, "endpoint": "http://wsus.example.test:8530/ClientWebService/wusserverversion.xml", "httpStatus": 200, "error": ""})
        with patch.object(tram_agent, "powershell", side_effect=lambda script, **_: (scripts.append(script) or (0, response))):
            result = tram_agent.windows_update_source_probe({"sourceMode": "wsus", "wsusServer": "http://wsus.example.test:8530"})
        encoded = scripts[0].split("FromBase64String('", 1)[1].split("')", 1)[0]
        endpoints = json.loads(base64.b64decode(encoded).decode())
        self.assertTrue(result["reachable"])
        self.assertIn("/ClientWebService/wusserverversion.xml", endpoints[0])
        self.assertIn("/Selfupdate/wuident.cab", endpoints[1])
        self.assertIn("$request.Timeout=5000", scripts[0])
        self.assertIn("GetSystemWebProxy", scripts[0])

    def test_windows_update_query_pins_the_selected_source(self):
        scripts = []
        with patch.object(tram_agent, "powershell", side_effect=lambda script, **_: (scripts.append(script) or (0, "{}"))):
            tram_agent.windows_update_query(online=True, timeout=30, source_mode="wsus")
            tram_agent.windows_update_query(online=True, timeout=30, source_mode="windows_update")
        self.assertIn("$searcher.ServerSelection=1", scripts[0])
        self.assertIn("AddRows $result 'WSUS'", scripts[0])
        self.assertIn("$searcher.ServerSelection=2", scripts[1])
        self.assertIn("AddRows $result 'Windows Update'", scripts[1])

    def test_windows_update_cache_freshness_is_bounded(self):
        current = datetime.now(UTC).isoformat()
        self.assertTrue(tram_agent.windows_update_cache_is_fresh({"lastSearchSuccessDate": current}))
        self.assertFalse(tram_agent.windows_update_cache_is_fresh({"lastSearchSuccessDate": "2026-01-01T00:00:00+00:00"}))

    def test_windows_update_scan_does_not_treat_an_empty_recent_cache_as_complete(self):
        environment = {
            "sourceMode": "wsus",
            "sourceLabel": "WSUS",
            "wsusServer": "http://wsus.example.test:8530",
            "policyIssue": "",
            "lastSearchSuccessDate": datetime.now(UTC).isoformat(),
        }
        cached = json.dumps({
            "platform": "windows",
            "updates": [],
            "diagnostics": {"currentScanComplete": False},
        })
        online = json.dumps({
            "platform": "windows",
            "updates": [{
                "id": "update-id",
                "revision": 1,
                "manager": "wua",
                "name": "Cumulative Update",
                "version": "KB5000001",
            }],
            "diagnostics": {"currentScanComplete": True},
        })
        queries = []

        def fake_query(**kwargs):
            queries.append(kwargs)
            return (0, online) if kwargs["online"] else (0, cached)

        with patch.object(tram_agent, "windows_update_environment", return_value=environment), \
             patch.object(tram_agent, "windows_configmgr_updates", return_value=[]), \
             patch.object(tram_agent, "windows_update_source_probe", return_value={"reachable": True, "status": "reachable", "endpoint": "http://wsus.example.test:8530", "error": ""}), \
             patch.object(tram_agent, "windows_update_query", side_effect=fake_query), \
             patch.object(tram_agent, "powershell", return_value=(0, "")):
            code, output = tram_agent.scan_windows_updates()

        parsed = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual([item["online"] for item in queries], [False, True])
        self.assertEqual(parsed["count"], 1)
        self.assertTrue(parsed["diagnostics"]["currentScanComplete"])
        self.assertEqual(parsed["diagnostics"]["wuaStatus"], "complete")
        self.assertEqual(parsed["diagnostics"]["cacheCount"], 0)

    def test_ubuntu_update_scan_reports_repository_failure_as_structured_status(self):
        commands = []
        def fake_command(name):
            return f"/usr/bin/{name}" if name in {"apt", "apt-get"} else None
        with patch.object(tram_agent, "find_system_command", side_effect=fake_command), \
             patch.object(tram_agent, "run", side_effect=lambda command, **_: (commands.append(command) or (100, "Temporary failure resolving archive.ubuntu.com"))):
            code, output = tram_agent.scan_updates({"os_family": "linux", "distribution_id": "ubuntu", "os_name": "Ubuntu", "os_version": "22.04"})
        parsed = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(len(commands), 1)
        self.assertIn("Acquire::http::Timeout=8", commands[0])
        self.assertEqual(parsed["updates"], [])
        self.assertFalse(parsed["diagnostics"]["currentScanComplete"])
        self.assertEqual(parsed["diagnostics"]["repositoryStatus"], "unreachable")
        self.assertEqual(parsed["diagnostics"]["osVersion"], "22.04")

    def test_oracle_update_scan_refreshes_only_the_configured_release_repositories(self):
        commands = []
        with patch.object(tram_agent, "find_system_command", side_effect=lambda name: "/usr/bin/yum" if name == "yum" else None), \
             patch.object(tram_agent, "run", side_effect=lambda command, **_: (commands.append(command) or (1, "Curl error (6): Could not resolve host"))):
            code, output = tram_agent.scan_updates({"os_family": "linux", "distribution_id": "ol", "os_name": "Oracle Linux Server", "os_version": "7.9"})
        parsed = json.loads(output)
        self.assertEqual(code, 0)
        self.assertIn("--setopt=metadata_expire=0", commands[0])
        self.assertIn("--setopt=skip_if_unavailable=False", commands[0])
        self.assertEqual(parsed["diagnostics"]["repositoryStatus"], "unreachable")
        self.assertEqual(parsed["diagnostics"]["osVersion"], "7.9")
        self.assertIn("installed OS release", parsed["diagnostics"]["applicabilityCriteria"])

    def test_windows_update_install_reuses_cached_catalog_and_checks_download(self):
        scan = json.dumps({"updates": [
            {"id": "wua-update-id", "revision": 4, "name": "Cumulative update", "version": "KB5012345", "manager": "wua", "serviceId": "service-guid"},
        ]})
        scripts = []
        with patch.object(tram_agent, "scan_updates", return_value=(0, scan)), patch.object(tram_agent, "powershell", side_effect=lambda script, **_: (scripts.append(script) or (0, '{"resultCode":2}'))):
            code, _ = tram_agent.install_updates({"updates": [{"id": "wua-update-id", "version": "KB5012345"}]}, {"os_family": "windows"})
        self.assertEqual(code, 0)
        self.assertIn("$searcher.Online=$false", scripts[0])
        self.assertIn("$searcher.ServerSelection=3", scripts[0])
        self.assertIn("$searcher.ServiceID=$serviceId", scripts[0])
        self.assertIn('Search("IsInstalled=0 and IsHidden=0")', scripts[0])
        self.assertIn("Start-Service -Name $serviceName", scripts[0])
        self.assertIn("$download.ResultCode -notin 2,3", scripts[0])

    def test_windows_update_install_treats_a_completed_missing_result_as_safe_noop(self):
        scan = json.dumps({
            "updates": [],
            "diagnostics": {"currentScanComplete": True, "catalogScope": "missing_on_this_server"},
        })
        with patch.object(tram_agent, "scan_updates", return_value=(0, scan)), patch.object(tram_agent, "powershell") as powershell_mock:
            code, output = tram_agent.install_updates(
                {"updates": [{"id": "obsolete-update-id", "version": "KB5012345"}]},
                {"os_family": "windows"},
            )
        parsed = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(parsed["status"], "skipped")
        self.assertEqual(parsed["reason"], "no_longer_applicable")
        self.assertEqual(parsed["currentMissingCount"], 0)
        powershell_mock.assert_not_called()
    def test_windows_update_install_rejects_an_incomplete_wua_scan(self):
        scan = json.dumps({
            "updates": [{"id": "wua-update-id", "revision": 4, "name": "Cached update", "version": "KB5012345", "manager": "wua", "serviceId": ""}],
            "diagnostics": {"currentScanComplete": False},
        })
        with patch.object(tram_agent, "scan_updates", return_value=(0, scan)):
            with self.assertRaisesRegex(ValueError, "scan is incomplete"):
                tram_agent.install_updates({"updates": [{"id": "wua-update-id", "version": "KB5012345"}]}, {"os_family": "windows"})

    def test_configmgr_update_install_uses_client_sdk(self):
        scan = json.dumps({"updates": [
            {"id": "ccm-update-id", "name": "Managed cumulative update", "version": "KB5012345", "manager": "configmgr"},
        ]})
        scripts = []
        with patch.object(tram_agent, "scan_updates", return_value=(0, scan)), patch.object(tram_agent, "powershell", side_effect=lambda script, **_: (scripts.append(script) or (0, '{"returnValue":0}'))):
            code, _ = tram_agent.install_updates({"updates": [{"id": "ccm-update-id", "version": "KB5012345"}]}, {"os_family": "windows"})
        self.assertEqual(code, 0)
        self.assertIn("CCM_SoftwareUpdatesManager", scripts[0])
        self.assertIn("InstallUpdates", scripts[0])
        self.assertIn("ccm-update-id", base64.b64decode(scripts[0].split("FromBase64String('", 1)[1].split("')", 1)[0]).decode())

    def test_update_install_rejects_a_stale_package_version(self):
        scan = json.dumps({"updates": [{"id": "openssl", "name": "openssl", "version": "3.0.2-2"}]})
        with patch.object(tram_agent, "scan_updates", return_value=(0, scan)):
            with self.assertRaisesRegex(ValueError, "changed"):
                tram_agent.install_updates({"updates": [{"id": "openssl", "version": "3.0.2-1"}]}, {"os_family": "linux", "distribution_id": "ubuntu"})

    def test_dnf_install_pins_only_the_selected_version(self):
        scan = json.dumps({"updates": [
            {"id": "openssl.x86_64", "name": "openssl", "version": "1:3.2.2-6.el9_5"},
            {"id": "curl.x86_64", "name": "curl", "version": "8.0.1-4.el9"},
        ]})
        commands = []
        with patch.object(tram_agent, "scan_updates", return_value=(0, scan)), patch.object(tram_agent, "find_system_command", side_effect=lambda name: "/usr/bin/dnf" if name == "dnf" else None), patch.object(tram_agent, "run", side_effect=lambda command, **_: (commands.append(command) or (0, "ok"))):
            code, _ = tram_agent.install_updates({"updates": [{"id": "openssl.x86_64", "version": "1:3.2.2-6.el9_5"}]}, {"os_family": "linux", "distribution_id": "rhel"})
        self.assertEqual(code, 0)
        self.assertEqual(commands, [["/usr/bin/dnf", "-y", "upgrade", "openssl.x86_64-1:3.2.2-6.el9_5"]])

    def test_account_group_update_preserves_builtin_memberships(self):
        snapshot = {
            "groups": [
                {"name": "Users", "protected": True},
                {"name": "Administrators", "protected": True},
                {"name": "AppOps", "protected": False},
            ],
            "adminGroups": ["Administrators"],
            "defaultGroups": ["Users"],
        }
        desired = tram_agent.desired_account_groups(snapshot, ["AppOps"], False, {"Users", "Administrators"})
        self.assertEqual(desired, {"Users", "AppOps"})
        desired_admin = tram_agent.desired_account_groups(snapshot, ["AppOps"], True, {"Users"})
        self.assertEqual(desired_admin, {"Users", "Administrators", "AppOps"})

    def test_log_severity_matches_words_not_substrings(self):
        self.assertEqual(tram_agent.normalize_severity("", "server started normally"), "info")
        self.assertEqual(tram_agent.normalize_severity("", "service failed to start"), "error")
        self.assertEqual(tram_agent.normalize_severity("", "warning: disk latency"), "warning")

    def test_logs_reject_a_source_not_scanned_from_the_server(self):
        available = json.dumps([{"id": "journal", "type": "journal"}])
        with patch.object(tram_agent, "log_sources", return_value=(0, available)):
            with self.assertRaisesRegex(ValueError, "changed"):
                tram_agent.read_logs({"limit": 500, "sources": ["/etc/shadow"]}, False)

    def test_process_kill_protects_init_and_the_agent(self):
        with self.assertRaisesRegex(ValueError, "protected"):
            tram_agent.kill_processes({"processes": [{"pid": 1, "name": "systemd", "created": 1.0}]})
        with self.assertRaisesRegex(ValueError, "protected"):
            tram_agent.kill_processes({"processes": [{"pid": tram_agent.os.getpid(), "name": "python", "created": 1.0}]})

    def test_process_sampler_is_single_pass_cached_and_handles_pid_reuse(self):
        now = [10.0]
        process = SimpleNamespace(
            pid=101,
            info={
                "pid": 101,
                "name": "worker",
                "create_time": 1.0,
                "cpu_times": SimpleNamespace(user=1.0, system=1.0),
                "memory_info": SimpleNamespace(rss=100),
                "uids": SimpleNamespace(real=1000),
            },
            username=MagicMock(return_value="unexpected"),
        )
        sampler = tram_agent.ProcessSampler(cache_ttl=1.0, clock=lambda: now[0])
        with (
            patch.object(tram_agent.platform, "system", return_value="Linux"),
            patch.object(tram_agent.psutil, "process_iter", return_value=[process]) as process_iter,
            patch.object(tram_agent.psutil, "virtual_memory", return_value=SimpleNamespace(total=1000)),
            patch.object(tram_agent, "linux_username_for_uid", return_value="operator") as resolve_uid,
            patch.object(tram_agent.time, "sleep") as sleep,
        ):
            first = sampler.collect()
            cached = sampler.collect()
            self.assertEqual(process_iter.call_count, 1)
            self.assertEqual(first, cached)
            self.assertEqual(first[0]["cpuPercent"], 0.0)
            self.assertEqual(first[0]["memoryPercent"], 10.0)

            now[0] = 15.0
            process.info["cpu_times"] = SimpleNamespace(user=1.3, system=1.2)
            second = sampler.collect()
            self.assertEqual(process_iter.call_count, 2)
            self.assertEqual(second[0]["cpuPercent"], 10.0)
            self.assertEqual(resolve_uid.call_count, 1)

            now[0] = 20.0
            process.info["create_time"] = 2.0
            process.info["cpu_times"] = SimpleNamespace(user=9.0, system=1.0)
            reused = sampler.collect()
            self.assertEqual(reused[0]["cpuPercent"], 0.0)
            self.assertEqual(len(sampler._cpu_samples), 1)
            process.username.assert_not_called()
            sleep.assert_not_called()

    def test_host_metrics_sampler_is_non_blocking_and_caches_disk_usage(self):
        now = [200.0]
        with (
            patch.object(tram_agent.psutil, "boot_time", return_value=100.0),
            patch.object(tram_agent.psutil, "cpu_percent", side_effect=[0.0, 12.5, 13.5]) as cpu_percent,
            patch.object(tram_agent.psutil, "virtual_memory", return_value=SimpleNamespace(percent=50.0)),
            patch.object(tram_agent.psutil, "disk_partitions", return_value=[SimpleNamespace(mountpoint="/")]) as partitions,
            patch.object(tram_agent, "safe_disk_usage", return_value=SimpleNamespace(percent=40.0)) as disk_usage,
            patch.object(tram_agent.time, "time", return_value=1000.0),
        ):
            sampler = tram_agent.HostMetricsSampler(disk_interval=30.0, clock=lambda: now[0])
            sampler.prime_cpu()
            first = sampler.collect()
            now[0] = 205.0
            second = sampler.collect()

        self.assertEqual(first["cpu_percent"], 12.5)
        self.assertEqual(second["cpu_percent"], 13.5)
        self.assertEqual(second["disk_percent"], 40.0)
        self.assertEqual(second["uptime_seconds"], 900)
        self.assertEqual(partitions.call_count, 1)
        self.assertEqual(disk_usage.call_count, 1)
        self.assertEqual(cpu_percent.call_count, 3)
        for call in cpu_percent.call_args_list:
            self.assertIsNone(call.kwargs["interval"])

    def test_signing_material_is_reused_until_identity_files_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = tram_agent.ec.generate_private_key(tram_agent.ec.SECP256R1())
            subject = tram_agent.x509.Name([
                tram_agent.x509.NameAttribute(tram_agent.NameOID.COMMON_NAME, "agent-test"),
            ])
            now = datetime.now(UTC)
            certificate = (
                tram_agent.x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(private_key.public_key())
                .serial_number(tram_agent.x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .sign(private_key, tram_agent.hashes.SHA256())
            )
            (root / "agent.crt").write_bytes(certificate.public_bytes(tram_agent.serialization.Encoding.PEM))
            (root / "agent.key").write_bytes(
                private_key.private_bytes(
                    tram_agent.serialization.Encoding.PEM,
                    tram_agent.serialization.PrivateFormat.PKCS8,
                    tram_agent.serialization.NoEncryption(),
                )
            )
            config = tram_agent.Config(str(root / "agent.json"))
            with (
                patch.object(
                    tram_agent.x509,
                    "load_pem_x509_certificate",
                    wraps=tram_agent.x509.load_pem_x509_certificate,
                ) as certificate_loader,
                patch.object(
                    tram_agent.serialization,
                    "load_pem_private_key",
                    wraps=tram_agent.serialization.load_pem_private_key,
                ) as key_loader,
            ):
                first = tram_agent.signed_headers(config, "POST", "https://control.example/api/checkin", b"one")
                second = tram_agent.signed_headers(config, "POST", "https://control.example/api/checkin", b"two")

            self.assertEqual(certificate_loader.call_count, 1)
            self.assertEqual(key_loader.call_count, 1)
            self.assertEqual(first["X-Tram-Agent-Certificate"], second["X-Tram-Agent-Certificate"])
            self.assertNotEqual(first["X-Tram-Agent-Signature"], second["X-Tram-Agent-Signature"])

    def test_one_shot_loop_reuses_initial_inventory_and_http_session(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename in ("agent.crt", "agent.key", "agent-ca.crt"):
                (root / filename).write_text("test", encoding="ascii")
            config = tram_agent.Config(str(root / "agent.json"))
            config.agent_endpoint = "https://control.example/api/v1/agent"
            response = MagicMock()
            response.json.return_value = {"jobs": []}
            session = MagicMock()
            session.post.return_value = response
            inventory = {"os_family": "linux", "distribution_id": "ubuntu"}
            with (
                patch.object(tram_agent.requests, "Session", return_value=session),
                patch.object(tram_agent, "collect_inventory", return_value=inventory) as collect_inventory,
                patch.object(tram_agent, "collect_metrics", return_value={}),
                patch.object(tram_agent, "ensure_server_ca"),
                patch.object(tram_agent, "signed_request", return_value=(b"{}", {})),
                patch.object(tram_agent._HOST_METRICS_SAMPLER, "prime_cpu"),
            ):
                tram_agent.loop(config, once=True)

            self.assertEqual(collect_inventory.call_count, 1)
            self.assertEqual(session.post.call_count, 1)
            session.close.assert_called_once_with()
    def test_process_sampler_coalesces_concurrent_requests(self):
        entered = tram_agent.threading.Event()
        release = tram_agent.threading.Event()
        process = SimpleNamespace(
            pid=202,
            info={
                "pid": 202,
                "name": "worker",
                "create_time": 2.0,
                "cpu_times": SimpleNamespace(user=1.0, system=0.0),
                "memory_info": SimpleNamespace(rss=10),
                "uids": SimpleNamespace(real=1000),
            },
        )

        def processes(*_args, **_kwargs):
            entered.set()
            self.assertTrue(release.wait(2))
            return [process]

        sampler = tram_agent.ProcessSampler(cache_ttl=1.0, clock=lambda: 10.0)
        with (
            patch.object(tram_agent.platform, "system", return_value="Linux"),
            patch.object(tram_agent.psutil, "process_iter", side_effect=processes) as process_iter,
            patch.object(tram_agent.psutil, "virtual_memory", return_value=SimpleNamespace(total=100)),
            patch.object(tram_agent, "linux_username_for_uid", return_value="operator"),
            tram_agent.ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(sampler.collect)
            self.assertTrue(entered.wait(2))
            second = executor.submit(sampler.collect)
            release.set()
            self.assertEqual(first.result(timeout=2), second.result(timeout=2))

        self.assertEqual(process_iter.call_count, 1)

    def test_process_sampler_keeps_windows_process_when_username_is_denied(self):
        process = SimpleNamespace(
            pid=303,
            info={
                "pid": 303,
                "name": "System",
                "create_time": 3.0,
                "cpu_times": SimpleNamespace(user=0.0, system=1.0),
                "memory_info": SimpleNamespace(rss=50),
            },
            username=MagicMock(side_effect=tram_agent.psutil.AccessDenied(pid=303)),
        )
        sampler = tram_agent.ProcessSampler(cache_ttl=1.0, clock=lambda: 10.0)
        with (
            patch.object(tram_agent.platform, "system", return_value="Windows"),
            patch.object(tram_agent.psutil, "process_iter", return_value=[process]),
            patch.object(tram_agent.psutil, "virtual_memory", return_value=SimpleNamespace(total=1000)),
        ):
            rows = sampler.collect()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["pid"], 303)
        self.assertIsNone(rows[0]["username"])

if __name__ == "__main__":
    unittest.main()
