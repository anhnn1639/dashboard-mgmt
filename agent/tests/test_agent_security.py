import importlib.util
import base64
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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
            tram_agent.shrink_storage({"kind": "windows_partition", "disk_number": 0, "partition_number": 3, "shrink_bytes": 1024**3}, True)
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

    def test_command_timeout_is_reported_without_crashing_the_agent(self):
        timeout = subprocess.TimeoutExpired(["slow-command"], 7, output="partial output")
        with patch.object(tram_agent.subprocess, "run", side_effect=timeout):
            code, output = tram_agent.run(["slow-command"], timeout=7)
        self.assertEqual(code, 124)
        self.assertIn("timed out after 7 seconds", output)
        self.assertIn("partial output", output)

    def test_linux_service_allows_netlink_for_inventory_and_firewall(self):
        service = (MODULE_PATH.parent / "tram-agent.service").read_text(encoding="utf-8")
        address_families = next(line for line in service.splitlines() if line.startswith("RestrictAddressFamilies="))
        self.assertIn("AF_NETLINK", address_families.split("=", 1)[1].split())

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

        with patch.object(tram_agent.shutil, "which", side_effect=fake_which), patch.object(tram_agent, "run", side_effect=fake_run):
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

        with patch.object(tram_agent.shutil, "which", side_effect=fake_which), patch.object(tram_agent, "run", side_effect=fake_run):
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

    def test_windows_storage_scan_reports_ordered_free_segments_and_resize_limits(self):
        scripts = []
        with patch.object(tram_agent, "powershell", side_effect=lambda script, **_: (scripts.append(script) or (0, '{"disks":[]}'))):
            code, _ = tram_agent.windows_storage_scan()
        self.assertEqual(code, 0)
        self.assertIn("Sort-Object Offset", scripts[0])
        self.assertIn("type='unallocated'", scripts[0])
        self.assertIn("offsetBytes", scripts[0])
        self.assertIn("shrinkableBytes", scripts[0])
        self.assertIn("largestFreeExtentBytes", scripts[0])
        self.assertIn("system|reserved|recovery|oem|unknown", scripts[0])

    def test_windows_shrink_rechecks_live_minimum_and_rejects_special_partitions(self):
        scripts = []
        with patch.object(tram_agent, "powershell", side_effect=lambda script, **_: (scripts.append(script) or (0, '{}'))):
            code, _ = tram_agent.shrink_storage(
                {"kind": "windows_partition", "disk_number": 0, "partition_number": 3, "shrink_bytes": 1024**3},
                True,
            )
        self.assertEqual(code, 0)
        self.assertIn("Get-PartitionSupportedSize", scripts[0])
        self.assertIn("SizeMin", scripts[0])
        self.assertIn("Resize-Partition", scripts[0])
        self.assertIn("recovery", scripts[0].lower())
        with self.assertRaisesRegex(ValueError, "Windows NTFS"):
            tram_agent.shrink_storage(
                {"kind": "windows_partition", "disk_number": 0, "partition_number": 3, "shrink_bytes": 1024**3},
                False,
            )

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
        with patch.object(tram_agent, "powershell", side_effect=lambda script, **kwargs: (calls.append((script, kwargs)) or (0, '{"updates":[]}'))):
            code, _ = tram_agent.scan_updates({"os_family": "windows"})
        scripts = [call[0] for call in calls]
        self.assertEqual(code, 0)
        self.assertEqual(calls[0][1]["timeout"], 180)
        self.assertIn('Search("IsInstalled=0 and IsHidden=0")', scripts[0])
        self.assertIn("$result.Updates.Item($i)", scripts[0])
        self.assertIn("$searcher.Online=$true", scripts[0])
        self.assertIn("$cachedSearcher.Online=$false", scripts[0])
        self.assertLess(scripts[0].index("$cachedSearcher.Online=$false"), scripts[0].index("$searcher.Online=$true"))
        self.assertIn("Start-Service -Name $serviceName", scripts[0])
        self.assertIn("$cachedSession=New-Object -ComObject Microsoft.Update.Session", scripts[0])
        self.assertIn("$onlineSession=New-Object -ComObject Microsoft.Update.Session", scripts[0])
        self.assertIn("Microsoft.Update.ServiceManager", scripts[0])
        self.assertIn("$serviceSearcher.ServerSelection=3", scripts[0])
        self.assertIn("$serviceSearcher.ServiceID", scripts[0])
        self.assertIn("currentScanComplete", scripts[0])
        self.assertIn("0x{0:X8}", scripts[0])
        self.assertIn("root\\ccm\\ClientSDK", scripts[0])
        self.assertIn("CCM_SoftwareUpdate", scripts[0])
        self.assertNotIn("foreach($u in $r.Updates)", scripts[0])

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


if __name__ == "__main__":
    unittest.main()
