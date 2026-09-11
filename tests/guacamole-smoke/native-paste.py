"""Trusted native clipboard gestures with Guacamole's real keyboard parser.

Only synthetic fixture text is copied in a disposable browser. Captured output
is an in-memory Guacamole clipboard/key stream, never a production connection.
"""
import asyncio
from pathlib import Path

HARNESS = r"""
window.fixture = { wire: [], remoteClipboard: '', reads: 0, writes: 0, active: true, mode: 'denied' };
const fixture = window.fixture;
const config = {}, runs = [];
const service = {
    resyncClipboard() {},
    setClipboard() { fixture.writes++; return new Promise(() => {}); }
};
const managed = { protocol: 'ssh', clientProperties: { focused: true }, clientState: { connectionState: 'CONNECTED' }, client: {
    sendKeyEvent(pressed, key) { fixture.wire.push(['key', pressed, key, fixture.remoteClipboard]); },
    sendMouseState() {},
    createClipboardStream(type) {
        fixture.wire.push(['clipboard', type]);
        let data = '';
        return {
            sendBlob(blob) { fixture.wire.push(['blob']); data += atob(blob); },
            sendEnd() {
                const bytes = Uint8Array.from(data, (char) => char.charCodeAt(0));
                fixture.remoteClipboard = new TextDecoder().decode(bytes);
                fixture.wire.push(['end', fixture.remoteClipboard]);
            }
        };
    }
} };
const Manager = { getManagedClients() { return fixture.active ? { test: managed } : {}; } };
const ManagedClient = { getInstance() { return managed; } };
const root = { $broadcast(name, data) {
    if (name === 'guacClipboard') {
        fixture.remoteClipboard = data.data;
        fixture.wire.push(['broadcast', data.data]);
    }
} };
class ClipboardData { constructor(data) { Object.assign(this, data); } }
window.angular = { module(name) { return {
    config(definition) { config[name] = definition.at(-1); },
    run(definition) { runs.push(definition); }
}; } };
window.addEventListener('paste', () => {
    if (fixture.loseFocusOnPaste) queueMicrotask(() => { fixture.active = false; });
}, true);
fixture.start = () => {
    config.clipboard({ decorator(name, definition) { definition.at(-1)(service, window, ClipboardData, root); } });
    config.client({ decorator(name, definition) { definition.at(-1)(ManagedClient); } });
    for (const definition of runs) {
        const dependencies = { $document: [document], $window: window, clipboardService: service, guacClientManager: Manager };
        definition.at(-1)(...definition.slice(0, -1).map((name) => dependencies[name]));
    }
    const client = ManagedClient.getInstance().client;
    const sink = new Guacamole.InputSink().getElement();
    document.body.appendChild(sink);
    fixture.sink = sink;
    const keyboard = new Guacamole.Keyboard(document);
    keyboard.listenTo(sink);
    keyboard.onkeydown = (key) => {
        if (!fixture.active || document.activeElement === document.querySelector('#local')) return true;
        client.sendKeyEvent(1, key); return false;
    };
    keyboard.onkeyup = (key) => {
        if (fixture.active && document.activeElement !== document.querySelector('#local')) client.sendKeyEvent(0, key);
    };
    window.addEventListener('blur', () => keyboard.reset());
    fixture.protocol = (value) => { managed.protocol = value; };
    fixture.state = (value) => { managed.clientState.connectionState = value; };
    fixture.resync = () => service.resyncClipboard(true);
    fixture.client = client;
    sink.focus();
};
Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
    readText() {
        fixture.reads++;
        if (fixture.mode === 'throw') throw new Error('fixture synchronous denial');
        if (fixture.mode === 'pending') return new Promise((resolve) => { fixture.finishRead = resolve; });
        if (fixture.mode === 'granted') return Promise.resolve('fresh fixture clipboard');
        return Promise.reject(new Error('fixture permission denied'));
    },
    writeText() { fixture.writes++; return new Promise(() => {}); }
} });
"""


async def verify_native_paste(browser, base_url, extension_path):
    context = await browser.new_context()
    try:
        page = await context.new_page()
        await page.route("**/native-paste-fixture", lambda route: route.fulfill(
            content_type="text/html", body='<html><body><textarea id="local"></textarea><button id="remote">Remote</button></body></html>'))
        await page.goto(base_url + "/native-paste-fixture")
        # Load the deployed library into the isolated harness. The complete
        # frontend above separately verifies browser loading of its own assets.
        # Avoid applying that application's response policies to our fake page.
        library = await context.request.get(base_url + "/guacamole-common-js/all.min.js")
        assert library.status == 200, ("Guacamole library", library.status)
        source = await library.text()
        assert "Guacamole" in source and "StringWriter" in source
        await page.add_script_tag(content=source)
        await page.add_script_tag(content=HARNESS)
        await page.add_script_tag(content=Path(extension_path).read_text(encoding="utf-8"))
        await page.evaluate("fixture.start()")
        for protocol in ('ssh', 'rdp'):
            await page.evaluate('(protocol) => fixture.protocol(protocol)', protocol)
            for shortcut in ("Control+v", "Control+Shift+v", "Shift+Insert"):
                for mode in ("denied", "throw", "pending"):
                    text = "Paste fixture tiếng Việt " + mode + " " + shortcut + "\nsecond line"
                    # Copy in a normal visible local editor: no clipboard-read permission.
                    await page.locator("#local").fill(text)
                    await page.locator("#local").press("Control+a")
                    await page.locator("#local").press("Control+c")
                    await page.evaluate("""(mode) => {
                        fixture.mode = mode; fixture.wire = []; fixture.sink.focus();
                        if (mode === 'pending') fixture.resync();
                    }""", mode)
                    await page.keyboard.press(shortcut)
                    await page.wait_for_function("fixture.wire.some((item) => item[0] === 'end')", timeout=4000)
                    await page.wait_for_timeout(50)
                    wire = await page.evaluate("fixture.wire")
                    ends = [item for item in wire if item[0] == "end"]
                    assert len(ends) == 1 and ends[0][1].replace("\r\n", "\n") == text, (shortcut, mode, "duplicate or incorrect fixture text")
                    delivered = ends[0][1]
                    paste_keysym = ord('V') if protocol == "ssh" else ord('v')
                    paste_keys = [item for item in wire if item[:3] == ["key", 1, paste_keysym]]
                    assert len(paste_keys) == 1 and paste_keys[0][3] == delivered, "Paste key preceded clipboard end"
                    text_keys = [item for item in wire if item[0] == "key" and item[1] == 1 and item[2] in (ord('v'), ord('V'), 0xFF63)]
                    assert text_keys == paste_keys, "Original shortcut leaked to remote alongside paste"
                    held = set()
                    for item in wire:
                        if item[0] != "key": continue
                        if item[1]: held.add(item[2])
                        else: held.discard(item[2])
                        if item[:3] == ["key", 1, paste_keysym]:
                            assert 0xFFE3 in held, "Paste lacked Control"
                            assert (0xFFE1 in held) == (protocol == "ssh"), "Wrong protocol paste shortcut"
                    assert not held, "Paste left a remote modifier pressed"
                    assert await page.evaluate("fixture.writes") == 0, "Incoming text attempted local clipboard writes"
                    if mode == "pending":
                        await page.evaluate("fixture.finishRead('stale fixture')")
                        await page.wait_for_timeout(30)
                        assert await page.evaluate("fixture.remoteClipboard") == delivered, "Late prompt overwrote native paste"

        # A visible local editor must retain its normal browser paste.
        await page.locator("#local").fill("")
        await page.evaluate("fixture.wire = []")
        await page.locator("#local").press("Control+v")
        assert await page.locator("#local").input_value() == text
        assert not await page.evaluate("fixture.wire.some((item) => item[0] === 'clipboard')")

        # Clipboard contents must not be sent to missing/disconnected sessions.
        for setup in ("fixture.active = false", "fixture.state('DISCONNECTED')", "fixture.protocol(null)"):
            await page.evaluate("fixture.active = true; fixture.state('CONNECTED'); fixture.protocol('rdp')")
            await page.evaluate(setup)
            await page.evaluate("fixture.wire = []; fixture.sink.focus()")
            await page.keyboard.press("Control+v")
            assert not await page.evaluate("fixture.wire.some((item) => item[0] === 'clipboard')")
        await page.evaluate("fixture.active = true; fixture.state('CONNECTED'); fixture.protocol('rdp')")

        # Check focus again after waiting for the superseded clipboard read.
        await page.evaluate("""() => {
            fixture.mode = 'pending'; fixture.resync(); fixture.wire = [];
            fixture.loseFocusOnPaste = true; fixture.sink.focus();
        }""")
        await page.keyboard.press("Control+v")
        await page.wait_for_function("fixture.active === false", timeout=3000)
        await page.wait_for_timeout(50)
        assert not await page.evaluate("fixture.wire.some((item) => item[0] === 'clipboard')")
        await page.evaluate("fixture.loseFocusOnPaste = false; fixture.active = true; fixture.finishRead('stale fixture')")

        # Native paste also works after clicking non-editable remote display content.
        await page.locator("#remote").click()
        await page.evaluate("fixture.wire = []")
        await page.keyboard.press("Control+v")
        await page.wait_for_function("fixture.wire.some((item) => item[0] === 'end')", timeout=3000)
        assert (await page.evaluate("fixture.remoteClipboard")).replace("\r\n", "\n") == text

        # A fabricated ClipboardEvent must not forward data to a connection.
        await page.evaluate("""() => {
            fixture.sink.focus(); fixture.wire = [];
            const data = new DataTransfer(); data.setData('text/plain', 'untrusted fixture');
            window.dispatchEvent(new ClipboardEvent('paste', { clipboardData: data, bubbles: true }));
        }""")
        assert not await page.evaluate("fixture.wire.some((item) => item[0] === 'clipboard')")

        # Granted read should publish immediately even if writeText never resolves.
        await page.evaluate("fixture.mode = 'granted'; fixture.resync()")
        await page.wait_for_function("fixture.remoteClipboard === 'fresh fixture clipboard'")
        assert await page.evaluate("fixture.writes") == 0
        print("PASS: native Ctrl+V/Ctrl+Shift+V/Shift+Insert, denied/pending clipboard, Unicode, no duplicate keys or stale writes")
    finally:
        await context.close()


if __name__ == "__main__":
    import sys
    from playwright.async_api import async_playwright
    async def main():
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            try:
                await verify_native_paste(browser, sys.argv[1], sys.argv[2])
            finally:
                await browser.close()
    asyncio.run(main())
