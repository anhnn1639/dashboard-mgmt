"""Browser regressions for shell fonts, About accessibility and build status.

Run against a production preview built from this checkout. All application APIs
are intercepted with synthetic data; no server, account or recording is changed.
DASHBOARD_BASE_URL defaults to http://127.0.0.1:3107.
"""
import asyncio
import json
import os
from urllib.parse import urlsplit
from urllib.request import urlopen

from playwright.async_api import async_playwright

BASE = os.environ.get("DASHBOARD_BASE_URL", "http://127.0.0.1:3107").rstrip("/")
if urlsplit(BASE).hostname not in {"127.0.0.1", "localhost", "::1"}:
    raise SystemExit("Use a local dashboard preview for this fixture.")


def current_build():
    with urlopen(BASE + "/build-info.json", timeout=10) as response:
        return json.load(response)["buildId"]


async def fixture(browser, build_id, theme="light", build_mode="current"):
    context = await browser.new_context(viewport={"width": 1440, "height": 960}, locale="vi-VN")
    await context.add_init_script("Date.prototype.getHours = () => " + ("9" if theme == "light" else "21") + ";")
    page = await context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    state = {"build_mode": build_mode, "writes": []}

    async def api(route):
        path = urlsplit(route.request.url).path
        if route.request.method not in {"GET", "HEAD"}:
            state["writes"].append((route.request.method, path))
        data = {"items": []}
        if path.endswith("/setup/status"):
            data = dict(setupRequired=False, databaseConfigured=True, databaseConnected=True,
                        schemaReady=True, adminExists=True, secretsReady=True,
                        dashboardUrl=BASE, setupTokenRequired=False, status="ready")
        elif path.endswith("/me"):
            data = dict(id="surface-fixture", username="surface-fixture", displayName="UI QA",
                        role="admin", source="local", mfaEnrolled=True,
                        permissions=["servers.view", "deletions.approve", "recordings.delete"])
        await route.fulfill(json=data)

    async def build(route):
        mode = state["build_mode"]
        if mode == "failed":
            return await route.fulfill(status=503, json={"detail": "fixture unavailable"})
        if mode == "invalid":
            return await route.fulfill(json={"buildId": ""})
        await route.fulfill(json={"buildId": build_id if mode == "current" else "fixture-next-build"})

    await page.route("**/api/**", api)
    await page.route("**/build-info.json?*", build)
    await page.goto(BASE + "/#/overview")
    await page.locator(".sidebar nav").wait_for()
    await page.evaluate("document.fonts.ready")
    return context, page, state, errors


async def modal_checks(page):
    trigger = page.get_by_role("button", name="Giới thiệu Operation Portal")
    await trigger.click()
    dialog = page.get_by_role("dialog", name="Operation Portal")
    await dialog.wait_for()
    close = dialog.get_by_role("button", name="Đóng", exact=True)
    assert await close.evaluate("element => element === document.activeElement"), "About must focus its close control"
    assert await dialog.evaluate("element => element.matches(':modal')"), "Background must be inert while About is open"
    for key in ["Tab", "Tab", "Shift+Tab", "Shift+Tab"]:
        await page.keyboard.press(key)
        assert await dialog.evaluate("element => element.contains(document.activeElement)"), "Keyboard focus escaped About"
    await page.set_viewport_size({"width": 390, "height": 380})
    bounds = await page.locator(".about-card").evaluate("""element => {
        const box = element.getBoundingClientRect();
        return {top: box.top, bottom: box.bottom, left: box.left, right: box.right,
                height: innerHeight, width: innerWidth, scroll: getComputedStyle(element).overflowY};
    }""")
    assert 0 <= bounds["top"] < bounds["bottom"] <= bounds["height"], bounds
    assert 0 <= bounds["left"] < bounds["right"] <= bounds["width"], bounds
    assert bounds["scroll"] == "auto", bounds
    await close.scroll_into_view_if_needed()
    await close.click()
    assert await dialog.count() == 0
    assert await trigger.evaluate("element => element === document.activeElement"), "Close did not restore focus"
    await trigger.click()
    await page.keyboard.press("Escape")
    assert await dialog.count() == 0, "Escape did not close About"
    assert await trigger.evaluate("element => element === document.activeElement"), "Escape did not restore focus"


async def notification_checks(browser, build_id):
    context, page, _, errors = await fixture(browser, build_id)
    operation = dict(id="volume-fixture", serverName="Linux QA", action="storage.delete",
                     parameters={"device": "/dev/qa-fixture-volume"}, reason="UI regression fixture",
                     status="pending", requestedBy="other-admin", requestedById="other-id",
                     createdAt="2026-01-01T00:00:00Z", expiresAt="2099-01-01T00:00:00Z")
    recording = dict(id="recording-fixture", sessions=[{"label": "RDP QA recording", "id": "session-fixture"}],
                     reason="UI regression fixture", status="pending", requestedBy="other-id",
                     requestedByUsername="other-admin", createdAt="2026-01-01T00:00:00Z")
    state = {"failed": False, "operations": [operation, dict(operation, id="expired-fixture", serverName="Expired QA", expiresAt="2000-01-01T00:00:00Z")], "posts": []}

    async def approvals(route):
        if state["failed"]:
            return await route.fulfill(status=503, json={"detail": "fixture unavailable"})
        await route.fulfill(json={"items": state["operations"]})

    async def review(route):
        state["posts"].append((route.request.method, urlsplit(route.request.url).path, route.request.post_data_json))
        state["operations"] = [item for item in state["operations"] if item["id"] != operation["id"]]
        await route.fulfill(json={"status": "approved"})

    await page.route("**/api/v1/deletion-approvals", approvals)
    await page.route("**/api/v1/deletion-approvals/*/review", review)
    await page.route("**/api/v1/recording-deletion-requests", lambda route: route.fulfill(json={"items": [recording]}))
    await page.reload()
    await page.locator(".notif-dot").get_by_text("2", exact=True).wait_for()
    await page.locator(".bell").click()
    panel = page.locator(".notif-panel")
    volume = panel.locator(".notif-item").filter(has_text="Linux QA")
    assert "/dev/qa-fixture-volume" in await volume.inner_text()
    assert "RDP QA recording" in await panel.inner_text()
    assert "Expired QA" not in await panel.inner_text()
    state["failed"] = True
    await page.evaluate("window.dispatchEvent(new Event('focus'))")
    await panel.get_by_role("alert").wait_for()
    assert await panel.locator(".notif-item").count() == 2
    assert "Không có yêu cầu nào" not in await panel.inner_text()
    assert await volume.get_by_role("button", name="Duyệt", exact=True).is_disabled()
    state["failed"] = False
    await panel.get_by_role("button", name="Thử tải lại", exact=True).click()
    await panel.get_by_role("alert").wait_for(state="hidden")
    confirmations = []

    async def accept(dialog):
        confirmations.append(dialog.message)
        await dialog.accept()

    page.once("dialog", accept)
    await volume.get_by_role("button", name="Duyệt", exact=True).click()
    await volume.wait_for(state="hidden")
    assert len(confirmations) == 1 and "/dev/qa-fixture-volume" in confirmations[0] and "Linux QA" in confirmations[0]
    assert state["posts"] == [("POST", "/api/v1/deletion-approvals/volume-fixture/review", {"decision": "approve"})], state["posts"]
    assert await panel.locator(".notif-item").count() == 1
    assert not errors, errors
    await context.close()
    print("PASS notifications: exact targets, expiry, failed poll preserves rows, retry, confirmed review removes row")


async def main():
    build_id = await asyncio.to_thread(current_build)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        for theme in ["light", "dark"]:
            context, page, state, errors = await fixture(browser, build_id, theme, "new")
            fonts = await page.evaluate("""() => ({
                ui: getComputedStyle(document.body).fontFamily,
                data: getComputedStyle(document.querySelector('.system-time b')).fontFamily,
                uiAlias: getComputedStyle(document.body).getPropertyValue('--font-geist-sans'),
                dataAlias: getComputedStyle(document.body).getPropertyValue('--font-geist-mono')
            })""")
            assert "Be Vietnam Pro" in fonts["ui"] and fonts["uiAlias"].strip(), fonts
            assert "IBM Plex Mono" in fonts["data"] and fonts["dataAlias"].strip(), fonts
            if theme == "light":
                contrast = await page.locator(".security-card p").evaluate(r"""element => {
                    function luminance(color) {
                        const channels = color.match(/[\d.]+/g).slice(0, 3).map(Number).map(value => {
                            value /= 255;
                            return value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4;
                        });
                        return channels[0] * .2126 + channels[1] * .7152 + channels[2] * .0722;
                    }
                    const text = luminance(getComputedStyle(element).color);
                    const background = luminance(getComputedStyle(element.closest('.security-card')).backgroundColor);
                    return (Math.max(text, background) + .05) / (Math.min(text, background) + .05);
                }""")
                assert contrast >= 4.5, f"Security card text contrast is {contrast}"
            await modal_checks(page)
            assert not errors, errors
            assert not state["writes"], state["writes"]
            await context.close()
            print(f"PASS {theme}: UI/data fonts, modal focus/restore/Escape, small viewport" + (", security contrast" if theme == "light" else ""))

        for mode, expected in [("failed", "Chưa kiểm tra được"), ("invalid", "Chưa kiểm tra được"),
                               ("current", "Đang dùng bản triển khai hiện tại"), ("new", "Có bản mới")]:
            context, page, state, errors = await fixture(browser, build_id, build_mode=mode)
            await page.get_by_role("button", name="Giới thiệu Operation Portal").click()
            await page.get_by_role("dialog").get_by_text(expected, exact=True).wait_for()
            text = await page.get_by_role("dialog").inner_text()
            assert "support@anhnn.vn" not in text and "1.8.0" not in text and "không giới hạn máy chủ" not in text, text
            if mode in {"failed", "invalid"}:
                assert "Mới nhất" not in text and "Đang dùng bản triển khai hiện tại" not in text, text
            assert not errors, errors
            assert not state["writes"], state["writes"]
            await context.close()
            print(f"PASS build status: {mode}")
        await notification_checks(browser, build_id)
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
