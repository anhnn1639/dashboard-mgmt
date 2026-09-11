"""Autofill policy and real DOM regressions using disposable credentials only."""
import asyncio
import os
import time
import unittest
import uuid
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from unittest.mock import AsyncMock, patch

from auto_login import ActivationRequest, LoginCredentials, SavedAccountLogin
import browser_worker as w
from playwright.async_api import async_playwright
from pydantic import ValidationError


class LoginPolicyTests(unittest.IsolatedAsyncioTestCase):
    def test_activation_secret_is_redacted_and_never_accepted_by_prepare_or_discovery(self):
        credentials = {"username": "fixture-user", "password": "fixture-password"}
        payload = ActivationRequest(credentials=credentials)
        self.assertNotIn("fixture-password", repr(payload))
        self.assertNotIn("fixture-user", repr(payload))
        with self.assertRaises(ValidationError):
            w.CreateSession(session_id=uuid.uuid4(), target_url="https://console.test", credentials=credentials)
        with self.assertRaises(ValidationError):
            w.DiscoverRequest(target_url="https://console.test", credentials=credentials)

    async def test_activation_only_starts_login_after_transport_and_stop_clears_it(self):
        desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(), target_url="https://console.test"))
        credentials = LoginCredentials(username="fixture-user", password="fixture-password")
        with self.assertRaises(w.HTTPException):
            await desktop.activate(credentials)
        self.assertIsNone(desktop.login)
        desktop.status = "connected"
        desktop.navigate = AsyncMock()
        with patch.object(SavedAccountLogin, "run", new_callable=AsyncMock) as run:
            await desktop.activate(credentials)
            await asyncio.sleep(0)
            run.assert_awaited_once()
            with self.assertRaises(w.HTTPException):
                await desktop.activate(credentials)
            await desktop.stop()
        self.assertEqual(desktop.login.password, "")
        self.assertEqual(desktop.login.username, "")

    async def test_stalled_form_cancellation_clears_secrets(self):
        desktop = SimpleNamespace(input_enabled=lambda: True, automation_enabled=lambda: True, page=SimpleNamespace(frames=[]))
        login = SavedAccountLogin(desktop, LoginCredentials(username="fixture-user", password="fixture-password"))
        login.start()
        await asyncio.sleep(0)
        login.cancel()
        await asyncio.gather(login.task, return_exceptions=True)
        self.assertEqual((login.username, login.password), ("", ""))


@unittest.skipUnless(os.environ.get("TRAM_TEST_BROWSER"), "Real browser fixtures run in Web Console CI")
class LoginBrowserTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.pw = await async_playwright().start()
        browser = os.environ['TRAM_TEST_BROWSER']
        self.browser = await self.pw.chromium.launch(headless=True, chromium_sandbox=True,
            executable_path=None if browser == 'chromium' else browser)
        self.context = await self.browser.new_context()
        self.routes = {}
        self.posts = []
        self.reject_login = False
        self.post_delay = 0
        self.login = None
        async def route(request_route):
            request = request_route.request
            url = urlsplit(request.url)
            if request.method == 'POST':
                if self.post_delay:
                    await asyncio.sleep(self.post_delay)
                self.posts.append((url.hostname, url.path, parse_qs(request.post_data or '')))
                if url.path == '/first':
                    # Chromium bypasses route interception on HTTP redirect hops.
                    # Real HTTP 302 + two-step SSO is exercised by web-smoke.
                    await request_route.fulfill(content_type='text/html; charset=utf-8', body='<script>location.href="https://sso.test/password"</script>')
                else:
                    body = self.routes[('console.test', '/login')] if self.reject_login else '<h1>Signed in fixture</h1>'
                    await request_route.fulfill(content_type='text/html; charset=utf-8', body=body)
                return
            body = self.routes.get((url.hostname, url.path))
            if body is None:
                await request_route.abort()
            else:
                await request_route.fulfill(content_type='text/html; charset=utf-8', body=body)
        await self.context.route('**/*', route)
        self.page = await self.context.new_page()
        self.desktop = w.Desktop(w.CreateSession(session_id=uuid.uuid4(), target_url='https://console.test/login', allowed_origins=['https://sso.test']))
        self.desktop.page = self.page
        self.desktop.status = 'active'
        self.desktop.website_frame_ready = True  # DOM fixtures supply the recording gate separately.
        self.desktop.deadline = time.monotonic() + 120

    async def asyncTearDown(self):
        if self.login:
            self.login.cancel()
            if self.login.task:
                await asyncio.gather(self.login.task, return_exceptions=True)
        await self.browser.close()
        await self.pw.stop()

    async def open(self, html):
        self.routes[('console.test', '/login')] = html
        await self.page.goto('https://console.test/login')
        self.login = SavedAccountLogin(self.desktop, LoginCredentials(username='fixture-user', password='fixture-password'))

    async def run_login(self):
        self.login.start()
        await asyncio.wait_for(self.login.task, 8)
        self.assertEqual((self.login.username, self.login.password), ('', ''))

    async def wait_for_posts(self, count):
        # A frame click can complete before its network handler observes the POST.
        # Wait for the observed request, without resubmitting the login form.
        async with asyncio.timeout(3):
            while len(self.posts) < count:
                await asyncio.sleep(.01)
        self.assertEqual(self.login.state, 'submitted')

    async def test_login_waits_for_first_website_frame_and_capture_recovery(self):
        await self.open('<form method="post"><input name="username"><input type="password" name="password"><button>Login</button></form>')
        self.desktop.website_frame_ready = False
        self.login.start()
        await asyncio.sleep(.3)
        self.assertEqual(await self.page.locator('input[name=username]').input_value(), '')
        self.assertFalse(self.posts)
        self.desktop.website_frame_ready = True
        self.desktop.capture_recovering = True
        await asyncio.sleep(.3)
        self.assertEqual(await self.page.locator('input[name=password]').input_value(), '')
        self.assertFalse(self.posts)
        self.desktop.capture_recovering = False
        await asyncio.wait_for(self.login.task, 8)
        await self.wait_for_posts(1)
        self.assertEqual(len(self.posts), 1)
        self.assertEqual((self.login.username, self.login.password), ('', ''))

    async def test_standard_vcenter_style_form_is_filled_and_submitted_once(self):
        await self.open('<form method="post" action="/login"><input id="userName" name="username"><input id="password" type="password" name="password"><button id="submit">Login</button></form>')
        await self.run_login()
        await self.wait_for_posts(1)
        self.assertEqual(self.posts, [('console.test', '/login', {'username':['fixture-user'], 'password':['fixture-password']})])
        self.assertEqual(self.login.state, 'submitted')
        await asyncio.sleep(.6)
        self.assertEqual(len(self.posts), 1)

    async def test_rejected_password_is_not_automatically_retried(self):
        self.reject_login = True
        await self.open('<form method="post"><input name="username"><input name="password" type="password"><button>Login</button></form>')
        await self.run_login()
        await self.wait_for_posts(1)
        await self.page.locator('input[name=password]').wait_for()
        await asyncio.sleep(.7)
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(self.login.state, 'submitted')
        self.assertEqual(await self.page.locator('input[name=password]').input_value(), '')

    async def test_username_first_redirect_to_saved_sso_then_password(self):
        self.routes[('sso.test','/password')] = '<form method="post" action="/finish"><input type="password" name="password" autocomplete="current-password"><button>Sign in</button></form>'
        await self.open('<form method="post" action="/first"><input name="username" autocomplete="username"><button>Next</button></form>')
        await self.run_login()
        await self.wait_for_posts(2)
        self.assertEqual(len(self.posts), 2)
        self.assertEqual(self.posts[0][2], {'username':['fixture-user']})
        self.assertEqual(self.posts[1], ('sso.test','/finish',{'password':['fixture-password']}))

    async def test_delayed_form_and_same_origin_iframe(self):
        self.post_delay = .1
        self.routes[('console.test','/frame')] = '<script>setTimeout(()=>document.body.innerHTML=\'<form method="post" action="/finish"><input name="username"><input name="password" type="password"><button>Đăng nhập</button></form>\',800)</script><body>Loading</body>'
        await self.open('<iframe src="/frame"></iframe>')
        await self.run_login()
        await self.wait_for_posts(1)
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(self.posts[0][2]['password'], ['fixture-password'])

    async def test_external_frame_and_external_form_action_receive_no_password(self):
        self.routes[('sso.test','/frame')] = '<form method="post"><input name="username"><input type="password" name="password"><button>Login</button></form>'
        await self.open('<iframe src="https://sso.test/frame"></iframe><form method="post" action="https://outside.test/login"><input name="username"><input type="password" name="password"><button>Login</button></form>')
        for frame in self.page.frames:
            self.assertFalse(await self.login.attempt(frame))
            for field in await frame.locator('input').all():
                self.assertEqual(await field.input_value(), '')
        self.assertFalse(self.posts)
        await self.page.locator('form').evaluate("e=>e.action='/login'")
        await self.page.locator('button').evaluate("e=>e.setAttribute('formaction','https://outside.test/login')")
        self.assertFalse(await self.login.attempt(self.page.main_frame))
        self.assertEqual(await self.page.locator('input[type=password]').input_value(), '')

    async def test_otp_new_password_and_manual_input_are_preserved(self):
        for fields in ('<input autocomplete="one-time-code" name="otp">', '<input autocomplete="new-password" type="password" name="newpassword">'):
            await self.open('<form method="post"><input name="username"><input type="password" name="password">'+fields+'<button>Login</button></form>')
            await self.run_login()
            self.assertEqual(self.login.state, 'manual-required')
            self.assertFalse(self.posts)
            self.assertEqual(await self.page.locator('input[name=password]').input_value(), '')
        await self.open('<form method="post"><input name="username" value="manually-entered"><input type="password" name="password"><button>Login</button></form>')
        await self.run_login()
        self.assertEqual(await self.page.locator('input[name=username]').input_value(), 'manually-entered')
        self.assertFalse(self.posts)

    async def test_disabled_password_does_not_submit_an_incomplete_login(self):
        await self.open('<form method="post"><input name="username"><input type="password" name="password" disabled><button>Login</button></form>')
        self.assertFalse(await self.login.attempt(self.page.main_frame))
        self.assertFalse(self.posts)
        self.assertFalse(self.login.username_submitted)
        await self.page.locator('input[name=password]').evaluate('e=>e.disabled=false')
        await self.run_login()
        await self.wait_for_posts(1)
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(self.posts[0][2], {'username':['fixture-user'], 'password':['fixture-password']})

    async def test_disabled_username_waits_and_readonly_other_account_is_not_used(self):
        await self.open('<form method="post"><input name="username" disabled><input type="password" name="password"><button>Login</button></form>')
        self.assertFalse(await self.login.attempt(self.page.main_frame))
        self.assertEqual(await self.page.locator('input[name=password]').input_value(), '')
        await self.page.locator('input[name=username]').evaluate("e=>{e.value='other-account';e.disabled=false;e.readOnly=true}")
        self.assertTrue(await self.login.attempt(self.page.main_frame))
        self.assertEqual(self.login.state, 'manual-required')
        self.assertEqual(await self.page.locator('input[name=password]').input_value(), '')
        self.assertFalse(self.posts)

    async def test_reset_action_named_submit_is_not_treated_as_login(self):
        await self.open('<form method="post"><input name="username"><input type="password" name="password"><button id="submit">Reset password</button></form>')
        self.assertFalse(await self.login.attempt(self.page.main_frame))
        self.assertEqual(await self.page.locator('input[name=password]').input_value(), '')
        self.assertFalse(self.posts)

    async def test_no_fill_without_active_recorded_lease(self):
        await self.open('<form method="post"><input name="username"><input type="password" name="password"><button>Login</button></form>')
        for status in ('waiting','connected','failed'):
            self.desktop.status = status
            self.assertFalse(await self.login.attempt(self.page.main_frame))
        self.desktop.status = 'active'
        self.desktop.deadline = time.monotonic()-1
        self.assertFalse(await self.login.attempt(self.page.main_frame))
        self.assertEqual(await self.page.locator('input[name=password]').input_value(), '')
        self.assertFalse(self.posts)


if __name__ == '__main__':
    unittest.main()
