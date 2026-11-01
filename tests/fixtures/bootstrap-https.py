"""Local TLS PIA API fixture; never contacts PIA or accepts real credentials."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import ssl
import struct
import threading
import time

control = Path('/control')


def dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 53))
    while True:
        query, peer = sock.recvfrom(512)
        index = 12
        labels = []
        while index < len(query) and query[index]:
            size = query[index]
            labels.append(query[index + 1:index + 1 + size].decode('ascii'))
            index += size + 1
        end = index + 5
        if end > len(query):
            continue
        name = '.'.join(labels)
        addresses = []
        if not (control / 'fail-dns').exists() and name in (
                'serverlist.piaservers.net', 'www.privateinternetaccess.com'):
            if query[index + 1:index + 3] == b'\x00\x01':
                addresses = (control / 'dns-addresses').read_text().split()
        flags = 0x8180 if addresses else 0x8183
        response = query[:2] + struct.pack('!HHHHH', flags, 1, len(addresses), 0, 0) + query[12:end]
        for address in addresses:
            response += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton(address)
        sock.sendto(response, peer)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        deadline = time.monotonic() + 20
        while (control / 'hold').exists() and time.monotonic() < deadline:
            time.sleep(.02)
        if self.path.endswith('/servers/v6'):
            body = (control / 'regions.json').read_bytes()
        elif self.path.endswith('/token'):
            body = (control / 'token.json').read_bytes()
        else:
            body = b'fixture-ok'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 < length <= 8192:
            self.send_error(400)
            return
        self.rfile.read(length)
        self.do_GET()


server = ThreadingHTTPServer(('0.0.0.0', 443), Handler)
threading.Thread(target=dns_server, daemon=True).start()
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/fixture/https.crt', '/fixture/https.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
