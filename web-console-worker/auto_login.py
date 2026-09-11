"""Bounded, one-attempt saved-account login inside a recorded browser."""
from __future__ import annotations

import asyncio
import time
from urllib.parse import urlsplit

from playwright.async_api import Error as BrowserError
from pydantic import BaseModel, ConfigDict, Field, SecretStr


class LoginCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=128, repr=False)
    password: SecretStr = Field(min_length=1, max_length=1024)


class ActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credentials: LoginCredentials | None = None


# Return DOM handles without reading website values or accepting credentials.
FIND_LOGIN = r"""() => {
  const visible = e => !e.disabled && !e.readOnly && e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden';
  const collect = root => [...root.querySelectorAll('input,button,[role="button"]')].concat(
    [...root.querySelectorAll('*')].filter(e => e.shadowRoot).flatMap(e => collect(e.shadowRoot)));
  const elements = collect(document);
  const displayedInputs = elements.filter(e => e.tagName === 'INPUT' && e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden');
  const inputs = displayedInputs.filter(visible);
  const hint = e => [e.id,e.name,e.autocomplete,e.getAttribute('aria-label'),e.placeholder,...(e.labels||[])].map(x=>typeof x==='string'?x:x?.textContent||'').join(' ').toLowerCase();
  const otp = e => /one-time-code|otp|captcha|verification|security.?code|mã xác|xac thuc/.test(hint(e));
  if (inputs.some(otp)) return {manual:true};
  const passwords = displayedInputs.filter(e => e.type === 'password');
  if (passwords.length > 1 || passwords.some(e => /new-password|new.?pass|confirm|repeat/.test(hint(e)))) return {manual:true};
  if (passwords.some(e => !visible(e))) return null;
  const password = passwords[0] || null;
  const namedUser = e => /username|user.?name|user.?id|j_username|email|login|account|tài khoản/.test(hint(e)) || e.autocomplete === 'username';
  let candidates = displayedInputs.filter(e => ['text','email','tel'].includes(e.type) && !otp(e));
  if (password?.form) candidates = candidates.filter(e => e.form === password.form);
  const named = candidates.filter(namedUser);
  const username = named.length === 1 ? named[0] : password && candidates.length === 1 ? candidates[0] : null;
  if (!password && !username) return null;
  const field = password || username;
  const form = field.form;
  const scope = form || field.closest('[role="form"],.login-form,.loginForm') || document;
  let buttons = elements.filter(e => visible(e) && (e.tagName === 'BUTTON' || ['submit','button'].includes(e.type) || e.getAttribute('role')==='button'));
  buttons = buttons.filter(e => form ? e.form === form : scope.contains(e));
  const label = e => (e.innerText || e.value || e.getAttribute('aria-label') || '').trim();
  const login = /^(log\s*in|sign\s*in|login|log\s*on|đăng\s*nhập|dang\s*nhap|anmelden|connexion)$/i;
  const next = /^(next|continue|tiếp\s*tục|tiep\s*tuc)$/i;
  const action = e => !/reset|change|delete|create|register|sign.?up|update|save|unlock|xóa|đổi|tạo/i.test(label(e)) && (login.test(label(e)) || /^(login|signin|logon)(button|btn)?$/i.test(e.id||'') || password && /^(submit)(button|btn)?$/i.test(e.id||'') && /^(submit)?$/i.test(label(e)));
  const matches = buttons.filter(e => password ? action(e) : action(e) || next.test(label(e)));
  if (matches.length !== 1 || (!password && !namedUser(username))) return null;
  return {username,password,button:matches[0],form,step:password?'password':'username'};
}"""


class SavedAccountLogin:
    def __init__(self, desktop, credentials: LoginCredentials):
        self.desktop = desktop
        self.username = credentials.username
        self.password = credentials.password.get_secret_value()
        self.task = None
        self.state = "waiting-form"
        self.username_submitted = False
        self.password_submitted = False

    def start(self):
        self.task = asyncio.create_task(self.run())

    def cancel(self):
        if self.task and not self.task.done():
            self.state = "manual-required"
            self.task.cancel()
        self.clear()

    def clear(self):
        self.username = self.password = ""

    def allowed(self, frame):
        page = self.desktop.page
        # Only the top-level website and its same-origin embedded login UI.
        return (self.desktop.automation_enabled() and self.desktop.permitted(page.url)
                and self.desktop.permitted(frame.url)
                and self.site(frame.url) == self.site(page.url))

    @staticmethod
    def site(url):
        parsed = urlsplit(url)
        return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)

    async def valid_action(self, frame, button):
        if not self.allowed(frame):
            return False
        destination = await button.evaluate("e => e.hasAttribute('formaction') ? e.formAction : e.form?.action || location.href")
        return (self.allowed(frame) and self.desktop.permitted(destination)
                and self.site(destination) == self.site(frame.url))

    async def attempt(self, frame):
        if not self.allowed(frame):
            return False
        found = await frame.evaluate_handle(FIND_LOGIN)
        handles = []
        try:
            properties = await found.get_properties()
            handles = list(properties.values())
            if properties.get("manual") and await properties["manual"].json_value():
                self.state = "manual-required"
                return True
            if "button" not in properties:
                return False
            button = properties["button"].as_element()
            username = properties["username"].as_element()
            password = properties["password"].as_element()
            step = await properties["step"].json_value()
            if not await self.valid_action(frame, button):
                return False
            if step == "username" and self.username_submitted:
                return False
            if username:
                current = await username.input_value()
                if current and current != self.username:
                    self.state = "manual-required"
                    return True
            if password and await password.input_value():
                self.state = "manual-required"
                return True
            if username and not await username.is_editable() and not current:
                return False
            if username and await username.is_editable() and self.allowed(frame):
                await username.fill(self.username, timeout=1500)
            if password:
                if not await self.valid_action(frame, button):
                    return False
                await password.fill(self.password, timeout=1500)
            if not await self.valid_action(frame, button):
                return False
            # A click/navigation timeout must not cause another password POST.
            if step == "password":
                self.password_submitted = True
                self.state = "submitted"
            else:
                self.username_submitted = True
                self.state = "waiting-password"
            await button.click(timeout=2000)
            return step == "password"
        finally:
            for handle in handles:
                await handle.dispose()
            await found.dispose()

    async def run(self):
        deadline = time.monotonic() + 45
        try:
            async with asyncio.timeout(45):
                while self.desktop.input_enabled() and time.monotonic() < deadline:
                    if not self.desktop.automation_enabled():
                        await asyncio.sleep(.1)
                        continue
                    for frame in list(self.desktop.page.frames):
                        try:
                            if await self.attempt(frame):
                                return
                        except BrowserError:
                            # DOM replacement during redirects is expected. Never
                            # print Playwright exceptions that may include secrets.
                            if self.password_submitted:
                                return
                    await asyncio.sleep(.5)
                self.state = "manual-required"
        except asyncio.CancelledError:
            if self.state != "submitted":
                self.state = "manual-required"
            raise
        except Exception:
            self.state = "manual-required"
        finally:
            self.clear()
