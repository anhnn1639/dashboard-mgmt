"""Real Guacamole frontend smoke inside the sandboxed browser image."""
import asyncio
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import sys
import time
from urllib.parse import quote

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from playwright.async_api import async_playwright


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
    base_url = sys.argv[1]
    key = os.environ["JSON_SECRET_KEY"]
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(chromium_sandbox=True)
        try:
            # A synchronous clipboard API failure used to abort Angular
            # startup. A pending prompt must not stop tunnel creation.
            for protocol, clipboard in (("ssh", "throw"), ("rdp", "pending")):
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
                url = base_url + "/#/client/" + identifier + "?data=" + quote(encrypted_fixture(key, protocol), safe="")
                await page.goto(url, wait_until="domcontentloaded")
                # The closed fixture port must produce the normal visible
                # Guacamole error. A black page cannot satisfy this check.
                await page.get_by_text("The remote desktop server", exact=False).first.wait_for(timeout=25000)
                assert tunnels, "Frontend never attempted a tunnel"
                assert not errors, "Frontend raised JavaScript exceptions"
                print("PASS: " + protocol + " frontend authenticates and shows connection failure with clipboard " + clipboard)
                await context.close()
            spec = importlib.util.spec_from_file_location("native_paste", "/fixture-native-paste.py")
            native_paste = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(native_paste)
            await native_paste.verify_native_paste(browser, base_url, "/fixture-clipboard.js")
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
