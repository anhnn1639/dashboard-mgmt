"""Exercise the real Guacamole image with disposable services and fake accounts.

All published ports bind loopback. The SSH/RDP destination is a closed loopback
port inside the disposable guacd container: the browser must show a connection
error instead of silently staying black. This verifies frontend/auth/transport,
not successful SSH/RDP authentication against a managed server.
"""
import asyncio
import base64
import contextlib
import hashlib
import hmac
import importlib.util
import json
import secrets
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import quote
from urllib.request import ProxyHandler, build_opener

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("guacamole_probe", ROOT / "deploy/verify-guacamole.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def docker(*args):
    result = subprocess.run(["docker", *args], text=True, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError("Disposable Guacamole Docker operation failed: " + args[0])
    return (result.stdout + (result.stderr if args[0] == "logs" else "")).strip()


def encrypted_fixture(key_hex, protocol):
    key = bytes.fromhex(key_hex)
    payload = {"username": "browser-fixture-" + protocol, "expires": int((time.time() + 90) * 1000),
               "connections": {"fixture-" + protocol: {"protocol": protocol, "parameters": {
                   "hostname": "127.0.0.1", "port": "1",
                   "username": "fixture-user", "password": "fixture-password",
                   "disable-copy": "true", "disable-paste": "false"}}}}
    body = json.dumps(payload, separators=(",", ":")).encode()
    signed = hmac.new(key, body, hashlib.sha256).digest() + body
    padder = padding.PKCS7(128).padder()
    padded = padder.update(signed) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    return base64.b64encode(cipher.update(padded) + cipher.finalize()).decode()


async def main():
    prefix = "portal-guacamole-" + secrets.token_hex(4)
    guacd, guacamole = prefix + "-guacd", prefix + "-web"
    key = secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix=prefix) as directory:
        envfile = Path(directory) / "guacamole.env"
        envfile.write_text("GUACD_HOSTNAME=guacd\nGUACD_PORT=4822\nJSON_ENABLED=true\nJSON_SECRET_KEY=" + key + "\n")
        envfile.chmod(0o600)
        docker("network", "create", prefix)
        try:
            docker("run", "-d", "--name", guacd, "--network", prefix,
                   "--network-alias", "guacd", "-p", "127.0.0.1::4822", "guacamole/guacd:1.6.0")
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

            async with async_playwright() as pw:
                browser = await pw.chromium.launch(chromium_sandbox=True)
                try:
                    # A synchronous clipboard API failure used to abort Angular
                    # startup. A pending prompt must not stop tunnel creation.
                    for protocol, clipboard in (("ssh", "throw"), ("rdp", "pending")):
                        protocol_marker = 'protocol "' + protocol + '"'
                        before = docker("logs", guacd).count(protocol_marker)
                        context = await browser.new_context(locale="en-US")
                        await context.add_init_script("""
                            Object.defineProperty(navigator, 'clipboard', {
                                configurable: true,
                                value: { readText() { """ + (
                                    "throw new Error('fixture synchronous clipboard denial');"
                                    if clipboard == "throw" else "return new Promise(() => {});"
                                ) + """ } }
                            });
                        """)
                        page = await context.new_page()
                        errors, tunnels = [], []
                        page.on("pageerror", lambda error: errors.append(type(error).__name__))
                        page.on("websocket", lambda ws: tunnels.append("websocket"))
                        page.on("request", lambda req: tunnels.append("http") if "/guacamole/tunnel" in req.url else None)
                        identifier = base64.urlsafe_b64encode(f"fixture-{protocol}\0c\0json".encode()).decode().rstrip("=")
                        url = probe.BASE_URL + "/#/client/" + identifier + "?data=" + quote(encrypted_fixture(key, protocol), safe="")
                        await page.goto(url, wait_until="domcontentloaded")
                        # The closed fixture port must produce the normal visible
                        # Guacamole error. A black page cannot satisfy this check.
                        await page.get_by_text("The remote desktop server", exact=False).first.wait_for(timeout=25000)
                        assert tunnels, "Frontend never attempted a tunnel"
                        assert not errors, "Frontend raised JavaScript exceptions"
                        assert docker("logs", guacd).count(protocol_marker) > before, "Browser tunnel never reached guacd"
                        with opener.open(probe.BASE_URL + "/app.js", timeout=5) as response:
                            assert b"clipboardDeadline" in response.read(1024 * 1024), "Stale extension"
                        print("PASS: " + protocol + " frontend authenticates and shows connection failure with clipboard " + clipboard)
                        await context.close()
                finally:
                    await browser.close()
            logs = docker("logs", guacd)
            # guacd writes its protocol logs to stdout in this image.
            for protocol in ("ssh", "rdp"):
                assert 'protocol "' + protocol + '"' in logs, "Guacd never received " + protocol
        finally:
            for container in (guacamole, guacd):
                with contextlib.suppress(Exception):
                    docker("rm", "-f", container)
            with contextlib.suppress(Exception):
                docker("network", "rm", prefix)


if __name__ == "__main__":
    asyncio.run(main())
