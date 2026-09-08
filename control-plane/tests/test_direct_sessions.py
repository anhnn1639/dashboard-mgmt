import asyncio
import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from app.direct_sessions import DirectSessionHub, SSHProbeError, _run_probe, discover_host_key


class DirectSessionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.callback = AsyncMock()
        self.hub = DirectSessionHub("127.0.0.1", self.callback)

    async def asyncTearDown(self):
        for identifier in list(self.hub.relays):
            await self.hub.cancel(identifier)

    async def test_only_fixed_unicast_ipv4_and_valid_port(self):
        for address, port in [("localhost", 22), ("127.0.0.1", 22), ("169.254.169.254", 22), ("224.0.0.1", 22), ("0.0.0.0", 22), ("10.8.1.2", 0), ("10.8.1.2", 65536)]:
            with self.assertRaises(ValueError):
                await self.hub.create_listener("id", "target", address, port)
        self.assertEqual(self.hub.relays, {})

    async def test_pending_limit_and_expiry_release_listener(self):
        for index in range(4):
            await self.hub.create_listener(str(index), "target", "10.8.1.2", 22)
        with self.assertRaises(ConnectionError):
            await self.hub.create_listener("fifth", "target", "10.8.1.2", 22)
        self.hub.ttl = .001
        await asyncio.gather(*(self.hub.expire(str(index)) for index in range(4)))
        self.assertFalse(self.hub.relays)
        self.assertEqual(self.callback.await_count, 4)

    async def test_single_use_bidirectional_relay_without_external_network(self):
        finished = asyncio.Event()

        async def echo(reader, writer):
            writer.write(b"SSH-test-banner")
            await writer.drain()
            data = await reader.read(1024)
            writer.write(data)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            finished.set()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        open_connection = asyncio.open_connection
        upstream_port = upstream.sockets[0].getsockname()[1]

        async def local_upstream(host, port):
            self.assertEqual((host, port), ("10.8.1.2", 2222))
            return await open_connection("127.0.0.1", upstream_port)

        try:
            port = await self.hub.create_listener("id", "target", "10.8.1.2", 2222)
            with patch("app.direct_sessions.asyncio.open_connection", side_effect=local_upstream):
                reader, writer = await open_connection("127.0.0.1", port)
                self.assertEqual(await asyncio.wait_for(reader.readexactly(15), 2), b"SSH-test-banner")
                writer.write(b"test-paste-command")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(18), 2), b"test-paste-command")
                await asyncio.wait_for(finished.wait(), 2)
                self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
                writer.close()
                await writer.wait_closed()
            for _ in range(20):
                if not self.hub.relays:
                    break
                await asyncio.sleep(.01)
            self.assertFalse(self.hub.relays)
            with self.assertRaises(OSError):
                await open_connection("127.0.0.1", port)
            self.callback.assert_awaited_once_with("id", "closed")
        finally:
            upstream.close()
            await upstream.wait_closed()

    async def test_discovery_is_no_shell_and_prefers_ecdsa_compatible_key(self):
        result = (b"[10.8.1.2]:2222 ssh-rsa dGVzdA==\n[10.8.1.2]:2222 ecdsa-sha2-nistp256 dGVzdA==\n", b"debug1: kex: algorithm: (no match)")
        with patch("app.direct_sessions._run_probe", new_callable=AsyncMock, return_value=result) as execute, patch("app.direct_sessions._discover_legacy_host_key", new_callable=AsyncMock) as legacy:
            self.assertEqual(await discover_host_key("10.8.1.2", 2222), "ecdsa-sha2-nistp256 dGVzdA==")
            self.assertEqual(execute.call_args.args[-1], "10.8.1.2")
            self.assertNotIn("shell", execute.call_args.kwargs)
            self.assertEqual(execute.call_args.args[0], "ssh-keyscan")
            legacy.assert_not_awaited()

    async def test_legacy_negotiation_automatically_falls_back_once_for_exact_target(self):
        result = (b"", b"debug1: kex: algorithm: (no match)")
        with patch("app.direct_sessions._run_probe", new_callable=AsyncMock, return_value=result), patch("app.direct_sessions._discover_legacy_host_key", new_callable=AsyncMock, return_value="ssh-rsa dGVzdA==") as legacy:
            self.assertEqual(await discover_host_key("10.8.1.2", 2222), "ssh-rsa dGVzdA==")
            legacy.assert_awaited_once_with("10.8.1.2", 2222)

    async def test_legacy_is_not_attempted_on_network_or_unknown_failure(self):
        for diagnostic, code in [(b"connect: Connection refused", "connection_refused"), (b"Connection timed out", "unreachable"), (b"untrusted remote banner", "handshake_failed"), (b"Permission denied (password).", "handshake_failed"), (b"REMOTE HOST IDENTIFICATION HAS CHANGED", "handshake_failed")]:
            with patch("app.direct_sessions._run_probe", new_callable=AsyncMock, return_value=(b"", diagnostic)), patch("app.direct_sessions._discover_legacy_host_key", new_callable=AsyncMock) as legacy:
                with self.assertRaises(SSHProbeError) as error:
                    await discover_host_key("10.8.1.2", 22)
                self.assertEqual(error.exception.code, code)
                self.assertNotIn(diagnostic.decode(), str(error.exception))
                legacy.assert_not_awaited()

    async def test_legacy_probe_has_minimal_algorithms_no_credentials_or_commands(self):
        async def run(*args):
            if args[0] == "ssh-keyscan":
                return b"", b"no matching key exchange method"
            self.assertEqual(args[-1], "10.8.1.2")
            self.assertIn("-N", args)
            self.assertIn("-T", args)
            self.assertIn("/dev/null", args)
            self.assertIn("KexAlgorithms=+diffie-hellman-group14-sha1", args)
            self.assertIn("PreferredAuthentications=none", args)
            self.assertIn("PasswordAuthentication=no", args)
            self.assertIn("IdentityAgent=none", args)
            self.assertIn("StrictHostKeyChecking=accept-new", args)
            self.assertIn("ClearAllForwardings=yes", args)
            self.assertFalse(any("group1-sha1" in arg or "cbc" in arg or "3des" in arg or "ssh-dss" in arg for arg in args))
            self.assertTrue(any(arg.startswith("UserKnownHostsFile=") and "tram-ssh-probe-" in arg for arg in args))
            return b"", b"Permission denied (password)."

        with patch("app.direct_sessions._run_probe", side_effect=run), patch.object(Path, "exists", return_value=True), patch.object(Path, "stat", return_value=SimpleNamespace(st_size=50)), patch.object(Path, "read_bytes", return_value=b"[10.8.1.2]:2222 ssh-rsa dGVzdA==\n"):
            self.assertEqual(await discover_host_key("10.8.1.2", 2222), "ssh-rsa dGVzdA==")

    async def test_legacy_does_not_accept_public_key_for_another_endpoint(self):
        with patch("app.direct_sessions._run_probe", new_callable=AsyncMock, return_value=(b"", b"no matching key exchange method")), patch.object(Path, "exists", return_value=True), patch.object(Path, "stat", return_value=SimpleNamespace(st_size=50)), patch.object(Path, "read_bytes", return_value=b"[10.8.1.9]:2222 ssh-rsa dGVzdA==\n"):
            with self.assertRaises(SSHProbeError) as error:
                await discover_host_key("10.8.1.2", 2222)
            self.assertEqual(error.exception.code, "algorithms_unsupported")

    async def test_automatic_fallback_failure_is_not_retried_or_hidden(self):
        for code in ("algorithms_unsupported", "timeout", "handshake_failed"):
            failure = SSHProbeError(code, "SSH probe failed")
            with patch("app.direct_sessions._run_probe", new_callable=AsyncMock, return_value=(b"", b"no matching key exchange method")) as modern, patch("app.direct_sessions._discover_legacy_host_key", new_callable=AsyncMock, side_effect=failure) as legacy:
                with self.assertRaises(SSHProbeError) as error:
                    await discover_host_key("10.8.1.2", 2222)
                self.assertIs(error.exception, failure)
                modern.assert_awaited_once()
                legacy.assert_awaited_once_with("10.8.1.2", 2222)

    async def test_probe_rejects_invalid_destinations_before_spawn(self):
        with patch("app.direct_sessions._run_probe", new_callable=AsyncMock) as probe:
            for address, port in [("127.0.0.1", 22), ("10.8.1.2", 0), ("10.8.1.2", 65536), ("10.8.1.2; id", 22)]:
                with self.assertRaises(ValueError):
                    await discover_host_key(address, port)
            probe.assert_not_awaited()

    async def test_probe_bounds_output_and_cleans_up_process(self):
        for output, expected in [(b"host key", None), (b"a" * 65537, "invalid_response")]:
            stdout, stderr = asyncio.StreamReader(), asyncio.StreamReader()
            stdout.feed_data(output)
            stdout.feed_eof()
            stderr.feed_eof()
            process = SimpleNamespace(stdout=stdout, stderr=stderr, returncode=None, kill=Mock(), wait=AsyncMock(return_value=0), communicate=AsyncMock(return_value=(b"", b"")))
            with patch("app.direct_sessions.asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=process) as spawn:
                if expected:
                    with self.assertRaises(SSHProbeError) as error:
                        await _run_probe("ssh-keyscan", "10.8.1.2")
                    self.assertEqual(error.exception.code, expected)
                else:
                    self.assertEqual(await _run_probe("ssh-keyscan", "10.8.1.2"), (output, b""))
                self.assertEqual(spawn.call_args.kwargs["stdin"], asyncio.subprocess.DEVNULL)
                self.assertNotIn("shell", spawn.call_args.kwargs)
                process.kill.assert_called_once()
                process.communicate.assert_awaited_once()

    async def test_probe_timeout_and_cancellation_kill_child(self):
        real_wait_for = asyncio.wait_for
        async def short_wait(awaitable, timeout):
            return await real_wait_for(awaitable, .001)
        for cancel in (False, True):
            process = SimpleNamespace(stdout=asyncio.StreamReader(), stderr=asyncio.StreamReader(), returncode=None, kill=Mock(), wait=AsyncMock(return_value=0), communicate=AsyncMock(return_value=(b"", b"")))
            with patch("app.direct_sessions.asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=process), patch("app.direct_sessions.asyncio.wait_for", side_effect=short_wait):
                task = asyncio.create_task(_run_probe("ssh-keyscan", "10.8.1.2"))
                if cancel:
                    await asyncio.sleep(0)
                    task.cancel()
                with self.assertRaises(asyncio.CancelledError if cancel else SSHProbeError):
                    await task
                process.kill.assert_called_once()
                process.communicate.assert_awaited_once()

    async def test_real_oversized_child_output_cannot_deadlock_cleanup(self):
        with self.assertRaises(SSHProbeError) as error:
            await asyncio.wait_for(_run_probe(sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 1048576); sys.stdout.flush()"), 5)
        self.assertEqual(error.exception.code, "invalid_response")

    async def test_missing_ssh_tool_has_actionable_error(self):
        with patch("app.direct_sessions.asyncio.create_subprocess_exec", new_callable=AsyncMock, side_effect=FileNotFoundError):
            with self.assertRaises(SSHProbeError) as error:
                await _run_probe("ssh-keyscan", "10.8.1.2")
            self.assertEqual(error.exception.code, "probe_unavailable")

    async def test_smoke_protocol_encoder_and_parser(self):
        path = Path(__file__).resolve().parents[2] / "tests" / "ssh-smoke" / "verify.py"
        spec = importlib.util.spec_from_file_location("ssh_smoke", path)
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        self.assertEqual(smoke.instruction("select", "ssh"), b"6.select,3.ssh;")
        reader = asyncio.StreamReader()
        reader.feed_data(smoke.instruction("args", "VERSION_1_5_0", "hostname", "port"))
        reader.feed_eof()
        self.assertEqual(await smoke.read_instruction(reader), ["args", "VERSION_1_5_0", "hostname", "port"])
