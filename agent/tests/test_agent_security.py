import importlib.util
import base64
import json
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
    def test_agent_version_comes_from_the_shared_version_file(self):
        expected = (MODULE_PATH.parent / "VERSION").read_text(encoding="ascii").strip()
        self.assertEqual(tram_agent.AGENT_VERSION, expected)
        wix_source = (MODULE_PATH.parent / "windows" / "Product.wxs").read_text(encoding="utf-8")
        self.assertIn('Version="$(var.AgentVersion)"', wix_source)

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
        with patch.object(tram_agent.shutil, "which", return_value=None):
            code, output = tram_agent.linux_firewall_rules()
        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(payload["backend"], "")
        self.assertIn("No active or supported firewall backend", payload["warning"])

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

    def test_iptables_rules_keep_per_chain_line_numbers(self):
        output = "*filter\n-A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -m comment --comment SSH -j ACCEPT\n-A INPUT -p udp --dport 53 -j DROP\nCOMMIT"
        rules = tram_agent.parse_iptables_rules(output, "ipv4")
        self.assertEqual([rule["spec"]["index"] for rule in rules], [1, 2])
        self.assertEqual(rules[0]["source"], "10.0.0.0/8")
        self.assertEqual(rules[1]["action"], "drop")

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

    def test_firewall_object_names_cannot_inject_commands(self):
        with patch.object(tram_agent.shutil, "which", return_value="/usr/sbin/nft"):
            with self.assertRaisesRegex(ValueError, "nftables target"):
                tram_agent.add_firewall_rule(
                    {"backend": "nftables", "name": "Web nội bộ", "direction": "in", "action": "allow", "protocol": "tcp", "local_port": 443, "source": "any", "destination": "any", "family": "inet", "table": "filter;reboot", "chain": "input"},
                    {"os_family": "linux"},
                )


if __name__ == "__main__":
    unittest.main()
