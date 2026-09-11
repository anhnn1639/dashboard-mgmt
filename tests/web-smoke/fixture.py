"""Disposable HTTPS form and forbidden TCP sinks. No production systems."""
import base64
import hashlib
import os
import socket
import socketserver
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs


class ForbiddenConnection(socketserver.BaseRequestHandler):
    def handle(self):
        # Mark TCP arrival, including TLS that would fail certificate validation.
        Path('/tmp/forbidden-hit').touch()


if len(sys.argv) > 1 and sys.argv[1] == 'sink':
    socketserver.ThreadingTCPServer(('0.0.0.0', 443), ForbiddenConnection).serve_forever()
    raise SystemExit

wrong_port = socketserver.ThreadingTCPServer(('0.0.0.0', 8443), ForbiddenConnection)
threading.Thread(target=wrong_port.serve_forever, daemon=True).start()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def minimal(self, body):
        # Disposable login pages contain only controlled fixture destinations.
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<!doctype html><html><body>' + body + b'</body></html>')

    def do_GET(self):
        Path('/tmp/visited').touch()
        if self.path == '/socket':
            assert self.headers.get('Upgrade', '').lower() == 'websocket'
            assert not self.headers.get('Proxy-Authorization')
            key = self.headers['Sec-WebSocket-Key']
            self.protocol_version = 'HTTP/1.1'
            self.send_response(101)
            self.send_header('Upgrade', 'websocket')
            self.send_header('Connection', 'Upgrade')
            self.send_header('Sec-WebSocket-Accept', base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode())
            self.end_headers()
            frame = self.rfile.read(2)
            assert frame[0] == 129 and frame[1] & 128 and frame[1] & 127 < 126
            mask = self.rfile.read(4)
            body = self.rfile.read(frame[1] & 127)
            assert bytes(value ^ mask[index % 4] for index, value in enumerate(body)) == b'fixture'
            self.wfile.write(b'\x81\x09confirmed'); self.wfile.flush()
            Path('/tmp/websocket-message').touch()
            return
        if self.path == '/discover':
            return self.minimal(b"<script>fetch('/discover-bootstrap').then(()=>location.href='https://sso.test:4443/discover-landing')</script>")
        if self.path == '/discover-bootstrap':
            time.sleep(6)
            return self.minimal(b'Bootstrap ready')
        if self.path == '/discover-landing':
            Path('/tmp/discover-landing-visited').touch()
            return self.minimal(b'<meta http-equiv="refresh" content="6;url=https://console.test/discover-final"><h1>Discovered SSO landing page</h1>')
        if self.path == '/discover-final':
            Path('/tmp/discover-final-visited').touch()
            return self.minimal(b'<h1>Discovery complete</h1>')
        if self.path == '/slow-font.woff2':
            Path('/tmp/font-requested').touch()
            time.sleep(12)
            Path('/tmp/font-response-finished').touch()
            self.send_error(404)
            return
        if self.path == '/ui':
            self.send_response(302)
            self.send_header('Location', '/websso/SAML2/SSO/fixture?SAMLRequest=disposable')
            self.end_headers()
            return
        if self.path == '/redirect-allowed':
            self.send_response(302)
            self.send_header('Location', 'https://sso.test:4443/ui')
            self.end_headers()
            return
        if self.path.startswith('/websso/SAML2/SSO/'):
            Path('/tmp/sso-visited').touch()
        if self.path in ('/redirect-ip', '/redirect-port'):
            Path('/tmp/' + self.path[1:] + '-attempted').touch()
            destination = ('https://' + socket.gethostbyname('forbidden.test') + '/blocked'
                           if self.path == '/redirect-ip' else 'https://console.test:8443/blocked')
            self.send_response(302)
            self.send_header('Location', destination)
            self.end_headers()
            return
        if self.path == '/checks-finished':
            Path('/tmp/redirect-checks-done').touch()
            self.send_response(204)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        delayed_font = b'<style>@font-face{font-family:DelayedFixture;src:url(/slow-font.woff2)}body{font-family:DelayedFixture,sans-serif!important}</style>' if os.environ.get('WEB_SMOKE_PROFILE') == 'delayed-font' else b''
        login_form = b'<form method="post"><input name="username" autocomplete="username" disabled><input name="password" type="password" autocomplete="current-password"><button id="submit">Login</button></form>' if os.environ.get('WEB_SMOKE_PROFILE') == 'auto-login' else b'<form method="post"><input name="value" disabled><button>Submit fixture</button></form>'
        self.wfile.write(b'<!doctype html><html>' + delayed_font + b"""<body style="background:#def;color:#123;font:24px sans-serif">
        <h1>Recorded internal console fixture</h1>
        """ + login_form + b"""
        <script>
        Promise.allSettled(['/redirect-ip','/redirect-port'].map(url=>fetch(url))).then(async results=>{
          if(!results.every(item=>item.status==='rejected')) return;
          await new Promise((resolve,reject)=>{
            const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/socket');
            ws.onopen=()=>ws.send('fixture'); ws.onerror=reject;
            ws.onmessage=event=>{if(event.data==='confirmed'){ws.close();resolve();}else reject();};
            setTimeout(reject,10000);
          });
          await fetch('/checks-finished');
          const input=document.querySelector('input'); input.disabled=false; input.focus();
        });
        </script></body></html>""")

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length > 1024:
            self.send_error(400)
            return
        body = self.rfile.read(length)  # Disposable fixtures only.
        if os.environ.get('WEB_SMOKE_PROFILE') == 'auto-login':
            values = parse_qs(body.decode())
            assert values == {'username': ['fixture-user'], 'password': ['fixture-password']}, 'Saved account did not reach the fixture'
            Path('/tmp/auto-login-submitted').touch()
        assert not self.headers.get('Proxy-Authorization'), 'Proxy credential reached website'
        Path('/tmp/submitted').touch()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1 style="color:green">Interaction received through recorded browser</h1>')


server = ThreadingHTTPServer(('0.0.0.0', 443), Handler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain('/fixture/server.crt', '/fixture/server.key')
server.socket = tls.wrap_socket(server.socket, server_side=True)
sso = ThreadingHTTPServer(('0.0.0.0', 4443), Handler)
sso.socket = tls.wrap_socket(sso.socket, server_side=True)
plain = ThreadingHTTPServer(('0.0.0.0', 8080), Handler)
for additional in (sso, plain):
    threading.Thread(target=additional.serve_forever, daemon=True).start()
server.serve_forever()
