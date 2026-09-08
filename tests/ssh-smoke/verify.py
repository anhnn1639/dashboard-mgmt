"""CI-only: real guacd -> single-use relay -> disposable SSH fixture + recording.

No production target, saved credential, or agent is used. The random fixture
password is passed through stdin/in-memory protocol only and never logged.
"""
import asyncio
import contextlib
import os
import secrets
import subprocess
import tempfile
import uuid
from pathlib import Path

from app.direct_sessions import DirectSessionHub, discover_host_key


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True, **kwargs).stdout.strip()


def instruction(*parts):
    return (",".join(f"{len(str(part))}.{part}" for part in parts) + ";").encode()


async def read_instruction(reader):
    result = []
    while True:
        size = int((await reader.readuntil(b"."))[:-1])
        if size > 8 * 1024 * 1024:
            raise RuntimeError("Oversized protocol element")
        result.append((await reader.readexactly(size)).decode())
        separator = await reader.readexactly(1)
        if separator == b";":
            return result
        if separator != b",":
            raise RuntimeError("Invalid protocol separator")


async def main():
    secret = secrets.token_urlsafe(24)
    docker("exec", "-i", "tram-smoke-sshd", "chpasswd", input=f"smoke:{secret}\n")
    address = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "tram-smoke-sshd")
    gateway = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", "tram-smoke-sshd")
    for attempt in range(30):
        try:
            key = await discover_host_key(address, 22)
            break
        except (OSError, ConnectionError):
            if attempt == 29:
                raise
            await asyncio.sleep(1)

    async def closed(_id, _reason):
        pass

    hub = DirectSessionHub("0.0.0.0", closed)
    with tempfile.TemporaryDirectory(prefix="tram-ssh-ci-") as directory:
        # Only this disposable CI output directory is shared with the test guacd.
        os.chmod(directory, 0o777)
        docker("run", "-d", "--name", "tram-smoke-guacd", "--network", "tram-smoke-net", "-p", "127.0.0.1:14822:4822", "-v", directory + ":/recordings", "guacamole/guacd:1.6.0")
        try:
            for attempt in range(30):
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", 14822)
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    if attempt == 29:
                        raise
                    await asyncio.sleep(1)

            for valid in (True, False):
                identifier = str(uuid.uuid4())
                port = await hub.create_listener(identifier, "fixture", address, 22)
                pin = key if valid else key[:-12] + ("A" if key[-12] != "A" else "B") + key[-11:]
                marker = "/tmp/tram-auth-ok" if valid else "/tmp/tram-pin-bypassed"
                parameters = {"hostname": gateway, "port": str(port), "username": "smoke", "password": secret, "host-key": f"[{gateway}]:{port} {pin}", "command": f"touch {marker}; printf 'SSH_SMOKE_OK\\n'; sleep 1", "recording-path": "/recordings", "recording-name": identifier, "create-recording-path": "true", "disable-copy": "true", "disable-paste": "false", "enable-sftp": "false"}
                reader, writer = await asyncio.open_connection("127.0.0.1", 14822)
                writer.write(instruction("select", "ssh"))
                await writer.drain()
                args = await asyncio.wait_for(read_instruction(reader), 10)
                if args[0] != "args":
                    raise RuntimeError("guacd did not offer connection parameters")
                writer.write(instruction("size", 1024, 768, 96) + instruction("audio") + instruction("video") + instruction("image", "image/png") + instruction("connect", *("VERSION_1_5_0" if name.startswith("VERSION_") else parameters.get(name, "") for name in args[1:])))
                await writer.drain()
                errored = False
                try:
                    async with asyncio.timeout(30):
                        while True:
                            message = await read_instruction(reader)
                            if message[0] == "error":
                                errored = True
                                break
                            if message[0] == "sync":
                                writer.write(instruction("sync", message[1]))
                                await writer.drain()
                            if message[0] == "disconnect":
                                break
                except asyncio.IncompleteReadError:
                    pass
                finally:
                    writer.close()
                    await writer.wait_closed()
                    await hub.cancel(identifier)
                if valid:
                    docker("exec", "tram-smoke-sshd", "test", "-f", marker)
                    if errored:
                        raise RuntimeError("Valid SSH session was rejected")
                    recording = Path(directory) / identifier
                    if not recording.exists() or recording.stat().st_size == 0:
                        raise RuntimeError("Session produced no recording")
                    print("PASS: real SSH password authentication through relay; nonempty Guacamole recording")
                else:
                    result = subprocess.run(["docker", "exec", "tram-smoke-sshd", "test", "-f", marker], capture_output=True)
                    if result.returncode == 0 or not errored:
                        raise RuntimeError("Incorrect SSH host key was not rejected")
                    print("PASS: incorrect host key rejected before remote command")
        finally:
            for identifier in list(hub.relays):
                await hub.cancel(identifier)
            # Fixture-only diagnostics; never print its generated password.
            for container in ("tram-smoke-guacd", "tram-smoke-sshd"):
                result = subprocess.run(["docker", "logs", container], capture_output=True, text=True)
                print(f"{container} diagnostics:\n" + (result.stdout + result.stderr).replace(secret, "[redacted]"))
            with contextlib.suppress(Exception):
                docker("rm", "-f", "tram-smoke-guacd")


asyncio.run(main())
