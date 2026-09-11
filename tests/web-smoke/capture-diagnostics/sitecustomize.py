"""Detailed screenshot errors only in the disposable web smoke container."""
from playwright.async_api import CDPSession

original_send = CDPSession.send


async def capture_diagnostics(self, method, params=None):
    try:
        return await original_send(self, method, params)
    except Exception as error:
        if method == "Page.captureScreenshot":
            print("Fixture CDP capture failure: " + repr(str(error))[:2000], flush=True)
        raise


CDPSession.send = capture_diagnostics
