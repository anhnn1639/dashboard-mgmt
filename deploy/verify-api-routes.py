"""Probe the running API after deployment; never authenticate or mutate data."""
import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener


REQUIRED_ROUTES = (
    "/api/v1/managed-targets",
    "/api/v1/deletion-approvals",
    "/api/v1/configuration-snapshot",
)


def verify_routes(opener, deadline_seconds=60):
    deadline = time.monotonic() + deadline_seconds
    for path in REQUIRED_ROUTES:
        while True:
            try:
                # Loopback only. Ignore proxy environment variables for this probe.
                request = Request("http://127.0.0.1:8000" + path, headers={"Accept": "application/json"})
                try:
                    response = opener.open(request, timeout=5)
                except HTTPError as error:
                    response = error
                with response:
                    status = response.code
                    body = response.read(4096)
                if status == 503 and time.monotonic() < deadline:
                    time.sleep(2)
                    continue
                if status != 401:
                    raise RuntimeError(f"API route {path}: expected HTTP 401 without credentials, got {status}. Rebuild/recreate API with the dashboard revision; do not accept a source-only grep check.")
                payload = json.loads(body)
                if not isinstance(payload, dict) or not isinstance(payload.get("detail"), str):
                    raise RuntimeError(f"API route {path}: response is not an API authentication error")
                print(f"API route ready and protected: {path}")
                break
            except (URLError, TimeoutError) as error:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"API did not become ready at {path}") from error
                time.sleep(2)


if __name__ == "__main__":
    verify_routes(build_opener(ProxyHandler({})))
