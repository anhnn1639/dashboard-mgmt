"""Disposable HTTPS form and forbidden TCP sinks. No production systems."""
import os
import socket
import socketserver
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


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
        self.wfile.write(b'<!doctype html><html>' + delayed_font + b"""<body style="background:#def;color:#123;font:24px sans-serif">
        <h1>Recorded internal console fixture</h1>
        <form method="post"><input name="value" disabled><button>Submit fixture</button></form>
        <script>
        Promise.allSettled(['/redirect-ip','/redirect-port'].map(url=>fetch(url))).then(async results=>{
          if(!results.every(item=>item.status==='rejected')) return;
          await fetch('/checks-finished');
          const input=document.querySelector('input'); input.disabled=false; input.focus();
        });
        </script></body></html>""")

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length > 1024:
            self.send_error(400)
            return
        self.rfile.read(length)  # Never retain or print input values.
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
