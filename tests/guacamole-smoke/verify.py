"""Exercise the real Guacamole image with disposable services and fake accounts.

All published ports bind loopback. The SSH/RDP destination is a closed loopback
port inside the disposable guacd container: the browser must show a connection
error instead of silently staying black. This verifies frontend/auth/transport,
then a real disposable SSH server verifies first paint and paste without any managed target.
"""
import asyncio
import contextlib
import importlib.util
import secrets
import socket
import subprocess
import tempfile
from pathlib import Path
from urllib.request import ProxyHandler, build_opener


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("guacamole_probe", ROOT / "deploy/verify-guacamole.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def docker(*args, **kwargs):
    result = subprocess.run(["docker", *args], text=True, capture_output=True, timeout=90, **kwargs)
    if result.returncode:
        # Only disposable services and credentials are used in this fixture.
        print((result.stdout + result.stderr)[-4000:])
        raise RuntimeError("Disposable Guacamole Docker operation failed: " + args[0])
    return (result.stdout + (result.stderr if args[0] == "logs" else "")).strip()


async def main():
    prefix = "portal-guacamole-" + secrets.token_hex(4)
    guacd, guacamole, browser_container = prefix + "-guacd", prefix + "-web", prefix + "-browser"
    sshd = prefix + "-sshd"
    ssh_password = secrets.token_urlsafe(24)
    key = secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix=prefix) as directory:
        recordings = Path(directory) / "recordings"
        results = Path(directory) / "paste-results"
        for path in (recordings, results):
            path.mkdir(mode=0o777)
            path.chmod(0o777)
        envfile = Path(directory) / "guacamole.env"
        envfile.write_text("GUACD_HOSTNAME=guacd\nGUACD_PORT=4822\nJSON_ENABLED=true\nJSON_SECRET_KEY=" + key + "\n")
        envfile.chmod(0o600)
        docker("network", "create", prefix)
        try:
            docker("run", "-d", "--name", sshd, "--network", prefix,
                   "-v", str(results) + ":/paste-results", "portal-guacamole-sshd")
            docker("exec", "-i", sshd, "chpasswd", input="smoke:" + ssh_password + "\n")
            ssh_key = " ".join(docker("exec", sshd, "cat", "/etc/ssh/ssh_host_ed25519_key.pub").split()[:2])
            with envfile.open("a") as stream:
                stream.write("SSH_FIXTURE_HOST=" + sshd + "\nSSH_FIXTURE_PASSWORD=" + ssh_password + "\nSSH_FIXTURE_KEY=" + ssh_key + "\n")
            docker("run", "-d", "--name", guacd, "--network", prefix,
                   "--network-alias", "guacd", "-p", "127.0.0.1::4822",
                   "-v", str(recordings) + ":/recordings", "guacamole/guacd:1.6.0")
            docker("run", "-d", "--name", guacamole, "--network", prefix,
                   "--env-file", str(envfile), "-p", "127.0.0.1::8080", "portal-guacamole-smoke")
            web_port = int(docker("port", guacamole, "8080/tcp").split(":")[-1])
            daemon_port = int(docker("port", guacd, "4822/tcp").split(":")[-1])
            probe.BASE_URL = f"http://127.0.0.1:{web_port}/guacamole"
            opener = build_opener(ProxyHandler({}))
            probe.verify_authentication(opener, key)
            probe.verify_stylesheet(opener)
            for protocol in ("ssh", "rdp"):
                probe.verify_protocol(protocol, connect=lambda address, timeout:
                                      socket.create_connection(("127.0.0.1", daemon_port), timeout))

            baseline = docker("logs", guacd)
            browser_output = docker("run", "--rm", "--name", browser_container, "--network", prefix, "--init", "--read-only",
                   "--cap-drop=ALL", "--security-opt", "no-new-privileges",
                   "--security-opt", "seccomp=" + str(ROOT / "web-console-worker/seccomp_profile.json"),
                   "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m,uid=10002,gid=10002",
                   "--tmpfs", "/home/worker:rw,nosuid,nodev,size=32m,uid=10002,gid=10002",
                   "--shm-size", "512m", "--env-file", str(envfile),
                   "-v", str(ROOT / "tests/guacamole-smoke/browser.py") + ":/fixture-browser.py:ro",
                   "-v", str(ROOT / "tests/guacamole-smoke/connected.py") + ":/fixture-connected.py:ro",
                   "-v", str(ROOT / "tests/guacamole-smoke/native-paste.py") + ":/fixture-native-paste.py:ro",
                   "-v", str(ROOT / "deploy/guacamole/clipboard-sync/tram-clipboard-sync-v5.js") + ":/fixture-clipboard.js:ro",
                   "--entrypoint", "python", "portal-guacamole-browser",
                   "/fixture-browser.py", f"http://{guacamole}:8080/guacamole")
            print(browser_output)
            for mode in ("granted", "denied", "pending"):
                assert (results / mode).read_text() == "SSH_PASTE_" + mode, "Native browser paste did not reach SSH exactly"
                recording = recordings / ("browser-" + mode)
                assert recording.is_file() and recording.stat().st_size > 0, "Connected browser session lacked recording"
            print("PASS: all browser SSH pastes verified on target; all three sessions recorded")
            logs = docker("logs", guacd)
            # Compare with the earlier probes; only browser-triggered attempts count.
            for protocol in ("ssh", "rdp"):
                marker = 'protocol "' + protocol + '"'
                assert logs.count(marker) > baseline.count(marker), "Browser never reached guacd for " + protocol
        finally:
            for container in (guacd, sshd):
                with contextlib.suppress(Exception):
                    print("Fixture diagnostics " + container + ":\n" + docker("logs", container).replace(ssh_password, "[redacted]")[-5000:])
            for container in (browser_container, guacamole, guacd, sshd):
                with contextlib.suppress(Exception):
                    docker("rm", "-f", container)
            with contextlib.suppress(Exception):
                docker("network", "rm", prefix)


if __name__ == "__main__":
    asyncio.run(main())
