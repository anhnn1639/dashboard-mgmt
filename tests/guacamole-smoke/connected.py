"""Full Guacamole frontend -> real SSH -> paste -> another rendered frame."""
import base64
import json
import os
from urllib.parse import quote

FRAME = """(color) => Array.from(document.querySelectorAll('canvas')).some((canvas) => {
    if (!canvas.checkVisibility()) return false;
    const rect = canvas.getBoundingClientRect();
    if (rect.width < 200 || rect.height < 100 || canvas.width < 50 || canvas.height < 50) return false;
    const pixel = canvas.getContext('2d').getImageData(20, 40, 1, 1).data;
    return pixel[3] === 255 && pixel[color] > 100
        && pixel[color] > pixel[0] + 50 && pixel[color] > pixel[3 - color] + 50;
})"""


async def prepare_late_layout(page):
    await page.route("**/app/element/templates/blank.html", lambda route: route.fulfill(
        content_type="text/html", headers={"X-Frame-Options": "DENY"}, body="<!doctype html><html></html>"))
    # Portal popups may finish auth while their display still has zero
    # dimensions. Guacamole must connect once layout becomes available.
    await page.add_init_script("""
        const observer = new MutationObserver(attach);
        function attach() {
            if (!document.documentElement) return;
            observer.disconnect();
            const style = document.createElement('style');
            style.textContent = '.client-main { width: 0 !important; height: 0 !important; }';
            document.documentElement.appendChild(style);
            window.fixtureReleaseLayout = () => style.remove();
        }
        observer.observe(document, {childList: true});
        attach();
    """)


async def release_late_layout(page):
    # Wait for the actual zero-size client, not an arbitrary delay.
    await page.wait_for_function("""() => {
        const main = document.querySelector('.client-main');
        return main && main.offsetWidth === 0 && main.querySelector('canvas');
    }""", timeout=15000)
    await page.evaluate("window.fixtureReleaseLayout()")


async def verify_connected_ssh(browser, base_url, key, encrypt):
    hostname = os.environ["SSH_FIXTURE_HOST"]
    password = os.environ["SSH_FIXTURE_PASSWORD"]
    public_key = os.environ["SSH_FIXTURE_KEY"]
    # Reuse browser auth storage across launches, just like Portal popup tabs.
    # Existing tabs must not force a new launch to reuse an older connection.
    context = await browser.new_context(locale="en-US")
    previous_page = None
    # Seed a valid legacy token whose connection goes to a closed port. Launches
    # must ignore it without deleting/revoking it out from under existing tabs.
    legacy = await context.request.post(base_url + "/api/tokens",
                                        form={"data": encrypt(key, "ssh")})
    assert legacy.status == 200, "Could not seed legacy fixture authentication"
    legacy_token = (await legacy.json())["authToken"]
    # SessionResource.checkValidity() has a void HEAD response (normally 204).
    # Check the baseline too, so a wrong endpoint/header cannot masquerade as
    # a later revocation failure. Neither request logs authentication data.
    legacy_headers = {"Guacamole-Token": legacy_token}
    valid = await context.request.head(base_url + "/api/session", headers=legacy_headers)
    assert valid.status in (200, 204), f"Legacy fixture session is invalid: HTTP {valid.status}"
    await context.add_init_script("localStorage.setItem('GUAC_AUTH_TOKEN', JSON.stringify("
                                  + json.dumps(legacy_token) + "));")
    try:
        for mode in ("granted", "denied", "pending"):
            # No real OS clipboard content is read by the asynchronous API.
            behavior = {
                "granted": "return Promise.resolve('older fixture text');",
                "denied": "return Promise.reject(new Error('fixture denial'));",
                "pending": "return new Promise(() => {});",
            }[mode]
            page = await context.new_page()
            await prepare_late_layout(page)
            await page.add_init_script("""Object.defineProperty(navigator, 'clipboard', {
                configurable: true, value: { readText() {""" + behavior + """},
                writeText() { return new Promise(() => {}); }
            }});""")
            errors = []
            page.on("pageerror", lambda error, target=errors: target.append(type(error).__name__))
            # Blue before paste, green only after the real remote shell reads it.
            command = ("printf '\\033[44m\\033[2J\\033[HSSH_READY\\n'; "
                       "IFS= read -r pasted; "
                       "printf '%s' \"$pasted\" > /paste-results/" + mode + "; "
                       "printf '\\033[42m\\033[2J\\033[HSSH_PASTE_RECEIVED\\n'; "
                       "sleep 30")
            parameters = {
                "hostname": hostname, "port": "22", "username": "smoke", "password": password,
                "host-key": hostname + " " + public_key,
                "command": command, "recording-path": "/recordings",
                "recording-name": "browser-" + mode, "create-recording-path": "true",
                "recording-include-keys": "false", "disable-copy": "true", "disable-paste": "false",
                "enable-sftp": "false",
            }
            identifier = base64.urlsafe_b64encode(b"fixture-ssh\0c\0json").decode().rstrip("=")
            url = base_url + "/#/client/" + identifier + "?data=" + quote(encrypt(key, "ssh", parameters), safe="")
            await page.goto(url, wait_until="domcontentloaded")
            await release_late_layout(page)
            try:
                await page.wait_for_function(FRAME, arg=2, timeout=20000)
            except Exception:
                print("Fixture first-frame diagnostics:", mode, errors,
                      (await page.locator("body").inner_text())[:500],
                      await page.locator("canvas").evaluate_all("""(canvases) => canvases.map(c => ({
                          width: c.width, height: c.height, visible: c.checkVisibility(),
                          rect: c.getBoundingClientRect().toJSON(),
                          pixel: c.width > 20 && c.height > 40 ? Array.from(c.getContext('2d').getImageData(20,40,1,1).data) : []
                      }))"""))
                raise

            # A separate page supplies a trusted copy, like an external editor.
            editor = await context.new_page()
            await editor.route("**/clipboard-copy-fixture", lambda route: route.fulfill(
                content_type="text/html", body='<textarea aria-label="Fixture text"></textarea>'))
            await editor.goto(base_url + "/clipboard-copy-fixture")
            await editor.locator("textarea").fill("SSH_PASTE_" + mode + "\n")
            await editor.locator("textarea").press("Control+a")
            await editor.locator("textarea").press("Control+c")
            await page.bring_to_front()
            await page.locator(".display").first.click(position={"x": 60, "y": 60})
            await page.keyboard.press("Control+v")
            await page.wait_for_function(FRAME, arg=1, timeout=10000)
            assert await page.locator("object.resize-sensor").count() == 0, "Display still depends on an embedded HTML object"
            prior_width = await page.locator(".client-main canvas").first.evaluate("(canvas) => canvas.width")
            await page.set_viewport_size({"width": 1000, "height": 650})
            await page.wait_for_function("""(priorWidth) => {
                const main = document.querySelector('.client-main');
                const canvas = main && main.querySelector('canvas');
                return main && main.offsetWidth > 900 && main.offsetHeight > 500
                    && canvas && canvas.width < priorWidth
                    && Math.abs(canvas.width - main.offsetWidth * devicePixelRatio) < 32;
            }""", arg=prior_width, timeout=10000)
            await page.wait_for_function(FRAME, arg=1, timeout=5000)
            assert not errors, "Connected Guacamole frontend raised a JavaScript error"
            if previous_page is not None:
                await previous_page.wait_for_function(FRAME, arg=1, timeout=2000)
                assert not await previous_page.get_by_text("The remote desktop server", exact=False).count()
            stored = await page.evaluate("JSON.parse(localStorage.getItem('GUAC_AUTH_TOKEN'))")
            assert stored == legacy_token, "New launch overwrote another tab's persistent authentication"
            valid = await context.request.head(base_url + "/api/session", headers=legacy_headers)
            assert valid.status in (200, 204), f"New launch revoked another tab's authentication: HTTP {valid.status}"
            previous_page = page
            print("PASS: real SSH browser recovers from zero-size layout with framing blocked, resizes, displays first frame, native paste reaches shell and next frame remains visible across shared browser auth; clipboard " + mode)
    finally:
        await context.close()
