"""Disposable HTTPS form. No production account or system is involved."""
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        Path('/tmp/visited').touch()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'''<!doctype html><html><body style="background:#def;color:#123;font:24px sans-serif">
        <h1>Recorded internal console fixture</h1>
        <form method="post"><input name="value" autofocus><button>Submit fixture</button></form>
        <script>fetch('https://outside.test/blocked').catch(()=>{});</script></body></html>''')

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length > 1024:
            self.send_error(400)
            return
        self.rfile.read(length)  # Never retain or print input values.
        Path('/tmp/submitted').touch()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1 style="color:green">Interaction received through recorded browser</h1>')


server = HTTPServer(('0.0.0.0', 443), Handler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain('/fixture/server.crt', '/fixture/server.key')
server.socket = tls.wrap_socket(server.socket, server_side=True)
server.serve_forever()
