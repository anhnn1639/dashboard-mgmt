"""Real guacd -> sandboxed Chromium -> disposable HTTPS target, with recording.

Run on a Docker-enabled Linux CI runner. All outputs, certificates and services
are temporary; the test never connects to production or decrypts a vault.
"""
import asyncio
import contextlib
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "control-plane"))
from app.web_sessions import WebSessionError, WebSessionHub


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()


def docker(*args, **kwargs):
    return run('docker', *args, **kwargs)


def instruction(*parts):
    return (','.join(f'{len(str(p))}.{p}' for p in parts) + ';').encode()


async def read_instruction(reader):
    result = []
    while True:
        size = int((await reader.readuntil(b'.'))[:-1])
        if size > 8 * 1024 * 1024:
            raise RuntimeError('Oversized protocol element')
        result.append((await reader.readexactly(size)).decode())
        if await reader.readexactly(1) == b';':
            return result


async def main():
    repository = Path(__file__).resolve().parents[2]
    profile = os.environ.get('WEB_SMOKE_PROFILE', 'trusted')
    if profile not in {'trusted', 'untrusted', 'legacy-false', 'redirect', 'http', 'delayed-font'}:
        raise ValueError('Unknown disposable web test profile')
    target_url = 'http://console.test:8080/ui' if profile == 'http' else 'https://console.test/' + ('redirect-allowed' if profile == 'redirect' else 'ui')
    secret = secrets.token_hex(16)
    token = hashlib.sha256(('tram-web-console:' + secret).encode()).hexdigest()
    clients = []
    hub = None
    with tempfile.TemporaryDirectory(prefix='tram-web-ci-') as directory:
        root = Path(directory)
        root.chmod(0o755)
        fixture, ca, recordings = (root / name for name in ('fixture', 'ca', 'recordings'))
        for path in (fixture, ca, recordings):
            path.mkdir()
            path.chmod(0o777 if path == recordings else 0o755)
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(fixture / 'ca.key'), '-out', str(ca / 'issuer.crt'), '-days', '1', '-subj', '/CN=Disposable web CI CA')
        run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(fixture / 'server.key'), '-out', str(fixture / 'server.csr'), '-subj', '/CN=console.test')
        (fixture / 'extensions').write_text('subjectAltName=DNS:console.test,DNS:sso.test\nextendedKeyUsage=serverAuth\n')
        run('openssl', 'x509', '-req', '-in', str(fixture / 'server.csr'), '-CA', str(ca / 'issuer.crt'), '-CAkey', str(fixture / 'ca.key'), '-CAcreateserial', '-out', str(fixture / 'server.crt'), '-days', '1', '-extfile', str(fixture / 'extensions'))
        (fixture / 'fixture.py').write_bytes((repository / 'tests/web-smoke/fixture.py').read_bytes())
        docker('network', 'create', 'tram-web-smoke')
        try:
            docker('run', '-d', '--name', 'tram-web-forbidden', '--network', 'tram-web-smoke', '--network-alias', 'forbidden.test', '-v', str(fixture) + ':/fixture:ro', 'python:3.12-bookworm', 'python', '/fixture/fixture.py', 'sink')
            docker('run', '-d', '--name', 'tram-web-fixture', '--network', 'tram-web-smoke', '--network-alias', 'console.test', '--network-alias', 'sso.test', '-e', 'WEB_SMOKE_PROFILE=' + profile, '-v', str(fixture) + ':/fixture:ro', 'python:3.12-bookworm', 'python', '/fixture/fixture.py')
            # Secret travels only via a private stdin env file, never argv/logs.
            envfile = root / 'worker.env'
            envfile.write_text('GUACAMOLE_JSON_SECRET=' + secret + '\n')
            envfile.chmod(0o600)
            trusted_ca = root / 'empty-ca' if profile in {'untrusted', 'legacy-false'} else ca
            trusted_ca.mkdir(exist_ok=True)
            trusted_ca.chmod(0o755)
            docker('run', '-d', '--name', 'tram-web-worker', '--network', 'tram-web-smoke', '--init', '--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges', '--security-opt', 'seccomp=' + str(repository / 'web-console-worker/seccomp_profile.json'), '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m,uid=10002,gid=10002', '--tmpfs', '/home/worker:rw,nosuid,nodev,size=32m,uid=10002,gid=10002', '--shm-size', '512m', '--env-file', str(envfile), '-v', str(trusted_ca) + ':/run/web-ca:ro', 'tram-web-smoke-worker')
            worker_ip = docker('inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', 'tram-web-worker')
            docker('run', '-d', '--name', 'tram-web-guacd', '--network', 'tram-web-smoke', '-p', '127.0.0.1:14822:4822', '-v', str(recordings) + ':/recordings', 'guacamole/guacd:1.6.0')
            base = 'http://' + worker_ip + ':8081'

            def http(method, path, body=None):
                request = Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                  headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
                with build_opener(ProxyHandler({})).open(request, timeout=35) as response:
                    return json.load(response)

            for attempt in range(45):
                try:
                    await asyncio.to_thread(http, 'GET', '/health')
                    break
                except Exception:
                    if attempt == 44:
                        raise
                    await asyncio.sleep(1)

            # Prove both forbidden sinks are actually listening, without
            # connecting to them or creating a false positive hit marker.
            for container, port in (('tram-web-forbidden', 443), ('tram-web-fixture', 8443)):
                check = "from pathlib import Path; assert any(line.split()[1].endswith(':%04X') and line.split()[3] == '0A' for line in Path('/proc/net/tcp').read_text().splitlines()[1:])" % port
                docker('exec', container, 'python', '-c', check)

            # Disposable-fixture diagnostics only; no production URL/account.
            preflight = """import asyncio, uuid
from playwright.async_api import async_playwright
from browser_worker import Desktop, CreateSession
async def check():
    async with async_playwright() as pw:
        d = Desktop(CreateSession(session_id=uuid.uuid4(), target_url='https://console.test/', width=800, height=600))
        try:
            await d.start(pw)
            print('Browser startup preflight passed')
        finally:
            await d.stop()
asyncio.run(check())
"""
            result = subprocess.run(['docker', 'exec', '-i', 'tram-web-worker', 'python', '-'], input=preflight, capture_output=True, text=True, timeout=45)
            print((result.stdout + result.stderr).replace(secret, '[redacted]')[-7000:])
            if result.returncode:
                raise RuntimeError('Isolated browser startup failed in disposable fixture')
            identifier = str(uuid.uuid4())
            hub = WebSessionHub(base, lambda: secret)
            if profile == 'legacy-false':
                # A stale API/config flag must no longer stop a certificate
                # used by the explicitly configured website origin.
                prepared = await hub.call('POST', '/sessions', {
                    'session_id': identifier, 'target_url': target_url,
                    'width': 1920, 'height': 1080, 'ignore_https_errors': False,
                    'allowed_origins': []})
            else:
                prepared = await hub.prepare(identifier, target_url, 1920, 1080,
                                             allowed_origins=['https://sso.test:4443'] if profile == 'redirect' else [])
            recording = recordings / (identifier + '.guac')
            activated = asyncio.Event()
            closures = []

            async def activate():
                assert recording.exists() and recording.stat().st_size > 0, 'Production watcher activated without a recording'
                assert subprocess.run(['docker', 'exec', 'tram-web-fixture', 'test', '-f', '/tmp/visited']).returncode != 0, 'Target opened before recording gate'
                await hub.call('POST', '/sessions/' + identifier + '/activate', {})
                activated.set()

            async def closed(_identifier, reason):
                closures.append(reason)

            # Exercise the same watcher as production, rather than manually
            # activating and renewing leases outside the recording watchdog.
            hub.watch(identifier, lambda: recording if recording.is_file() else None,
                      lambda: True, activate, closed)
            watcher = hub.tasks[identifier]
            self_test = subprocess.run(['docker', 'exec', 'tram-web-fixture', 'test', '-f', '/tmp/visited'])
            assert self_test.returncode != 0, 'Target opened before transport/recording'
            parameters = {'hostname': worker_ip, 'port': str(prepared['port']), 'password': prepared['password'], 'color-depth': '24', 'recording-path': '/recordings', 'create-recording-path': 'true', 'recording-name': identifier + '.guac', 'recording-exclude-output': 'false', 'recording-exclude-mouse': 'false', 'recording-exclude-touch': 'false', 'recording-include-keys': 'false', 'disable-copy': 'true', 'disable-paste': 'false'}
            for attempt in range(30):
                try:
                    reader, writer = await asyncio.open_connection('127.0.0.1', 14822)
                    writer.write(instruction('select', 'vnc')); await writer.drain()
                    args = await asyncio.wait_for(read_instruction(reader), 5)
                    if args[0] != 'args':
                        raise ConnectionError('guacd not ready')
                    break
                except (OSError, asyncio.IncompleteReadError, TimeoutError):
                    if attempt == 29:
                        raise
                    await asyncio.sleep(1)
            clients.append(writer)
            writer.write(instruction('size', 1920, 1080, 96) + instruction('audio') + instruction('video') + instruction('image', 'image/png') + instruction('connect', *('VERSION_1_5_0' if name.startswith('VERSION_') else parameters.get(name, '') for name in args[1:])))
            await writer.drain()
            errors = []
            images = []

            async def consume():
                try:
                    while True:
                        message = await read_instruction(reader)
                        if message[0] in {'img', 'png', 'jpeg'}:
                            images.append(message[0])
                        if message[0] == 'error':
                            errors.append(message[1]); return
                        if message[0] == 'sync':
                            writer.write(instruction('sync', message[1])); await writer.drain()
                except (asyncio.IncompleteReadError, ConnectionError):
                    pass

            consumer = asyncio.create_task(consume())
            def require_live():
                if closures:
                    raise RuntimeError('Production recording watcher closed browser: ' + closures[-1])
                if errors:
                    raise RuntimeError('guacd rejected browser transport: ' + errors[0])

            for _ in range(35):
                require_live()
                if activated.is_set():
                    break
                await asyncio.sleep(1)
            else:
                raise RuntimeError('Production recording watcher did not activate the browser')
            assert images, 'VNC transport produced no visible image before activation'
            # Browser clients resize the Guacamole display after connecting.
            writer.write(instruction('size', 1440, 900, 96))
            await writer.drain()
            first_size = recording.stat().st_size
            # Wait for both same-origin redirect requests to fail and prove that
            # no TCP connection reached either forbidden destination.
            for attempt in range(20):
                require_live()
                if subprocess.run(['docker', 'exec', 'tram-web-fixture', 'test', '-f', '/tmp/redirect-checks-done']).returncode == 0:
                    break
                await asyncio.sleep(1)
            else:
                raise RuntimeError('Redirect rejection fixture did not complete')
            for path in ('/tmp/redirect-ip-attempted', '/tmp/redirect-port-attempted'):
                assert subprocess.run(['docker', 'exec', 'tram-web-fixture', 'test', '-f', path]).returncode == 0
            for container in ('tram-web-fixture', 'tram-web-forbidden'):
                assert subprocess.run(['docker', 'exec', container, 'test', '-f', '/tmp/forbidden-hit']).returncode != 0, 'Forbidden redirect reached a TCP destination'
            if profile == 'delayed-font':
                # Keep the document open while its font is still unresolved.
                # Playwright page.screenshot(timeout=4000) waited for this font
                # and closed the old worker; the recording stream must survive.
                assert subprocess.run(['docker', 'exec', 'tram-web-fixture', 'test', '-f', '/tmp/font-requested']).returncode == 0, 'Delayed font fixture was not exercised'
                for _ in range(14):
                    require_live()
                    await asyncio.sleep(1)
                require_live()
                assert subprocess.run(['docker', 'exec', 'tram-web-fixture', 'test', '-f', '/tmp/font-response-finished']).returncode == 0, 'Delayed font never finished'
            submitted = False
            for attempt in range(12):
                require_live()
                if attempt == 3:
                    for key in (ord('a'), 0xff0d):
                        writer.write(instruction('key', key, 1) + instruction('key', key, 0))
                    await writer.drain()
                submitted = subprocess.run(['docker', 'exec', 'tram-web-fixture', 'test', '-f', '/tmp/submitted']).returncode == 0
                if submitted and recording.stat().st_size > first_size:
                    break
                await asyncio.sleep(1)
            assert submitted, 'Form interaction did not reach internal website fixture'
            assert subprocess.run(['docker', 'exec', 'tram-web-fixture', 'test', '-f', '/tmp/sso-visited']).returncode == 0, 'SSO redirect was not followed'
            assert recording.stat().st_size > first_size, 'Recording stopped growing'
            # Keep a mostly static page open past the recording-stall timeout.
            # This catches guacd buffering/delta-frame stalls that manual lease
            # refreshes would hide despite a healthy remote desktop stream.
            for _ in range(18):
                require_live()
                await asyncio.sleep(1)
            require_live()
            # Simulate the API losing its worker connection. The real watcher
            # fails closed but cannot deliver DELETE; the independent worker
            # lease must therefore expire without any manual stop request.
            with patch.object(hub, 'call', side_effect=WebSessionError('simulated-api-offline')):
                await asyncio.wait_for(asyncio.shield(watcher), 8)
            assert len(closures) == 1 and closures[0] in {'web-status-unavailable', 'web-lease-failed'}, closures
            await asyncio.sleep(17)
            state = await asyncio.to_thread(http, 'GET', '/sessions/' + identifier)
            assert state['status'] == 'failed' and state['reason'] == 'lease-expired', state
            consumer.cancel(); await asyncio.gather(consumer, return_exceptions=True)
            print('PASS: ' + profile + ' + production recording watcher + 1920x1080 Chromium + resized Guacamole VNC input + static-page recording; no target request before recording; literal-IP/wrong-port redirects blocked before TCP; API lease loss closes browser')
        finally:
            if hub is not None:
                await hub.shutdown()
            for writer in clients:
                writer.close()
            for container in ('tram-web-worker', 'tram-web-guacd', 'tram-web-fixture', 'tram-web-forbidden'):
                with contextlib.suppress(Exception):
                    result = subprocess.run(['docker', 'logs', container], capture_output=True, text=True)
                    print(container + ': ' + (result.stdout + result.stderr).replace(secret, '[redacted]')[-4000:])
                with contextlib.suppress(Exception):
                    docker('rm', '-f', container)
            with contextlib.suppress(Exception):
                docker('network', 'rm', 'tram-web-smoke')


if __name__ == '__main__':
    asyncio.run(main())
