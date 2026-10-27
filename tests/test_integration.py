"""Exercise the real proxy and web API against local synthetic servers only."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
from http.client import HTTPConnection, HTTPSConnection
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import ipaddress
import json
from pathlib import Path
import queue
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from mitmproxy import io


ROOT = Path(__file__).resolve().parents[1]
RESPONSE = gzip.compress(b'\x00synthetic upstream response\xff', mtime=0)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def read_exact(stream, count):
    result = b''
    while len(result) < count:
        part = stream.read(count - len(result))
        if not part:
            raise EOFError('Synthetic peer closed early')
        result += part
    return result


def read_frame(stream):
    first, second = read_exact(stream, 2)
    length = second & 127
    if length > 125:
        raise ValueError('Test fixture uses small frames only')
    mask = read_exact(stream, 4) if second & 128 else None
    body = read_exact(stream, length)
    if mask:
        body = bytes(byte ^ mask[index % 4] for index, byte in enumerate(body))
    return first & 15, body


class Origin(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.server.observed.put({
            'method': self.command, 'path': self.path, 'body': body,
            'duplicates': self.headers.get_all('X-Duplicate'),
            'cookie': self.headers.get('Cookie'),
            'authorization': self.headers.get('Authorization'),
            'host': self.headers.get('Host'),
            'origin': self.headers.get('Origin'),
            'referer': self.headers.get('Referer'),
        })
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Encoding', 'gzip')
        self.send_header('Content-Length', str(len(RESPONSE)))
        self.send_header('Set-Cookie', 'synthetic_a=one; HttpOnly')
        self.send_header('Set-Cookie', 'synthetic_b=two; HttpOnly')
        self.end_headers()
        self.wfile.write(RESPONSE)

    def do_GET(self):
        if self.path != '/ws':
            self.send_error(404)
            return
        key = self.headers['Sec-WebSocket-Key']
        accept = base64.b64encode(hashlib.sha1(
            (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()
        ).digest()).decode()
        self.send_response(101)
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Sec-WebSocket-Accept', accept)
        self.end_headers()
        self.wfile.flush()
        try:
            while True:
                opcode, body = read_frame(self.rfile)
                self.wfile.write(bytes([128 | opcode, len(body)]) + body)
                self.wfile.flush()
                if opcode == 8:
                    break
        except (EOFError, OSError):
            pass
        self.close_connection = True


def certificate(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Relay local test CA')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
                x509.DNSName('localhost'),
            ]), critical=False).sign(key, hashes.SHA256()))
    cert_path = directory / 'upstream-ca.pem'
    key_path = directory / 'upstream-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return cert_path, key_path


class ProxyIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='relay-test-')
        cls.directory = Path(cls.temporary.name)
        cls.data = cls.directory / 'data'
        cls.origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        cls.origin.observed = queue.Queue()
        cls.tls_origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        cls.tls_origin.observed = queue.Queue()
        ca, key = certificate(cls.directory)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ca, key)
        cls.tls_origin.socket = context.wrap_socket(cls.tls_origin.socket, server_side=True)
        cls.threads = []
        for server in (cls.origin, cls.tls_origin):
            thread = threading.Thread(target=server.serve_forever,
                                      kwargs={'poll_interval': 0.01}, daemon=True)
            thread.start()
            cls.threads.append(thread)
        cls.proxy_port = free_port()
        cls.web_port = free_port()
        while cls.web_port == cls.proxy_port:
            cls.web_port = free_port()
        cls.reverse_port = free_port()
        while cls.reverse_port in (cls.proxy_port, cls.web_port):
            cls.reverse_port = free_port()
        cls.process = subprocess.Popen([
            sys.executable, '-u', str(ROOT / 'relay.py'), '--no-browser',
            '--proxy-port', str(cls.proxy_port), '--web-port', str(cls.web_port),
            '--data-dir', str(cls.data), '--upstream-ca', str(ca),
            '--reverse', f'https://127.0.0.1:{cls.tls_origin.server_address[1]}',
            '--reverse-port', str(cls.reverse_port),
        ], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace')
        cls.addClassCleanup(cls.tearDownClass)
        cls.lines = queue.Queue()
        def collect():
            for line in cls.process.stdout:
                cls.lines.put(line)
        cls.reader = threading.Thread(target=collect, daemon=True)
        cls.reader.start()
        deadline = time.monotonic() + 35
        cls.token = None
        while time.monotonic() < deadline and cls.process.poll() is None:
            try:
                line = cls.lines.get(timeout=0.2)
            except queue.Empty:
                continue
            match = re.search(r'http://127\.0\.0\.1:\d+/\?token=([a-zA-Z0-9_-]+)', line)
            if match:
                cls.token = match.group(1)
                break
        if not cls.token:
            cls.tearDownClass()
            raise RuntimeError('Relay did not expose its authenticated local UI within 35 seconds')
        cls.jar = CookieJar()
        cls.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                urllib.request.HTTPCookieProcessor(cls.jar))
        # The login form (or the browser's WebSocket handshake) issues XSRF.
        # A bearer-authenticated GET of the SPA alone deliberately does not.
        try:
            cls.opener.open(cls.base_url() + '/', timeout=5)
        except urllib.error.HTTPError as error:
            if error.code != 403:
                raise
            error.read()
        with cls.opener.open(urllib.request.Request(
            cls.base_url() + '/', headers={'Authorization': 'Bearer ' + cls.token}), timeout=5
        ) as response:
            response.read()
        cls.xsrf = next(cookie.value for cookie in cls.jar if cookie.name == '_mitmproxy_xsrf')

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, 'process', None):
            cls.process.terminate()
            try:
                cls.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait(timeout=5)
            if cls.process.stdout:
                cls.process.stdout.close()
            cls.process = None
        for server in (getattr(cls, 'origin', None), getattr(cls, 'tls_origin', None)):
            if server:
                server.shutdown()
                server.server_close()
        cls.origin = None
        cls.tls_origin = None
        if getattr(cls, 'temporary', None):
            cls.temporary.cleanup()
            cls.temporary = None

    @classmethod
    def base_url(cls):
        return f'http://127.0.0.1:{cls.web_port}'

    def web(self, path, method='GET', data=None, content_type='application/json'):
        request = urllib.request.Request(self.base_url() + path, data=data, method=method,
            headers={'Authorization': 'Bearer ' + self.token,
                     'X-XSRFToken': self.xsrf, 'Content-Type': content_type,
                     'Sec-Fetch-Site': 'same-origin'})
        with self.opener.open(request, timeout=10) as response:
            return response.read()

    def forward(self, secure=False):
        server = self.tls_origin if secure else self.origin
        port = server.server_address[1]
        target = '/echo?x=%2f&x=two+words&empty='
        payload = b'\x00\xffbinary\r\n=payload&token=synthetic-fixture-only'
        if secure:
            context = ssl.create_default_context(cafile=str(self.data / 'ca' / 'mitmproxy-ca-cert.pem'))
            conn = HTTPSConnection('127.0.0.1', self.proxy_port, context=context, timeout=8)
            conn.set_tunnel('127.0.0.1', port)
            request_target = target
        else:
            conn = HTTPConnection('127.0.0.1', self.proxy_port, timeout=8)
            request_target = f'http://127.0.0.1:{port}' + target
        conn.putrequest('POST', request_target, skip_host=True, skip_accept_encoding=True)
        conn.putheader('Host', f'127.0.0.1:{port}')
        conn.putheader('X-Duplicate', 'first')
        conn.putheader('X-Duplicate', 'second')
        conn.putheader('Cookie', 'test_session=synthetic-cookie-value')
        conn.putheader('Authorization', 'Bearer synthetic-test-authorization')
        conn.putheader('Content-Type', 'application/octet-stream')
        conn.putheader('Content-Length', str(len(payload)))
        conn.endheaders(payload)
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader('Content-Encoding'), 'gzip')
        self.assertEqual(len([x for x in response.getheaders() if x[0].lower() == 'set-cookie']), 2)
        self.assertEqual(response.read(), RESPONSE)
        conn.close()
        observed = server.observed.get(timeout=5)
        self.assertEqual(observed['method'], 'POST')
        self.assertEqual(observed['path'], target)
        self.assertEqual(observed['body'], payload)
        self.assertEqual(observed['duplicates'], ['first', 'second'])
        self.assertEqual(observed['cookie'], 'test_session=synthetic-cookie-value')
        self.assertEqual(observed['authorization'], 'Bearer synthetic-test-authorization')
        dump = self.web('/flows/dump')
        flows = list(io.FlowReader(BytesIO(dump)).stream())
        matches = [flow for flow in flows if getattr(flow, 'request', None)
                   and flow.request.path == target and flow.request.port == port]
        self.assertTrue(matches)
        self.assertEqual(matches[-1].request.raw_content, payload)
        self.assertEqual(matches[-1].response.raw_content, RESPONSE)

    def test_http_preserves_binary_body_query_duplicate_headers_and_compressed_response(self):
        self.forward()

    def test_https_connect_verifies_tls_and_preserves_bodies(self):
        self.forward(secure=True)

    def test_web_ui_requires_authentication(self):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with self.assertRaises(urllib.error.HTTPError) as raised:
            opener.open(self.base_url() + '/flows', timeout=5)
        self.assertEqual(raised.exception.code, 403)

    def test_reverse_listener_preserves_origin_referer_and_body_with_fixed_tls_target(self):
        payload = b'local-client=exact%2f&payload=\x00\xff'
        conn = HTTPConnection('127.0.0.1', self.reverse_port, timeout=8)
        conn.request('POST', '/reverse?x=1&x=2', body=payload, headers={
            'Origin': 'http://local-client.invalid',
            'Referer': 'http://local-client.invalid/play?fixture=one',
            'Content-Type': 'application/octet-stream',
        })
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), RESPONSE)
        conn.close()
        observed = self.tls_origin.observed.get(timeout=5)
        self.assertEqual(observed['path'], '/reverse?x=1&x=2')
        self.assertEqual(observed['body'], payload)
        self.assertEqual(observed['origin'], 'http://local-client.invalid')
        self.assertEqual(observed['referer'], 'http://local-client.invalid/play?fixture=one')
        self.assertEqual(observed['host'], f'127.0.0.1:{self.tls_origin.server_address[1]}')

    def test_har_upload_is_offline_then_explicit_replay_sends_original_binary(self):
        payload = b'\x00\xffHAR\x80raw'
        port = self.origin.server_address[1]
        har = {'log': {'version': '1.2', 'creator': {'name': 'Relay test', 'version': '1'}, 'entries': [{
            'startedDateTime': '2026-10-27T10:00:00Z', 'time': 5,
            'request': {'method': 'POST', 'url': f'http://127.0.0.1:{port}/from-har?a=1&a=2',
                'httpVersion': 'HTTP/1.1', 'headers': [
                    {'name': 'Content-Type', 'value': 'application/octet-stream'},
                    {'name': 'Content-Length', 'value': str(len(payload))},
                    {'name': 'X-Duplicate', 'value': 'one'}, {'name': 'X-Duplicate', 'value': 'two'},
                ], 'cookies': [], 'queryString': [], 'headersSize': -1, 'bodySize': len(payload),
                'postData': {'mimeType': 'application/octet-stream', 'encoding': 'base64',
                             'text': base64.b64encode(payload).decode()}},
            'response': {'status': 200, 'statusText': 'OK', 'httpVersion': 'HTTP/1.1',
                'headers': [], 'cookies': [], 'content': {'size': 3, 'mimeType': 'text/plain', 'text': 'old'},
                'redirectURL': '', 'headersSize': -1, 'bodySize': 3},
            'cache': {}, 'timings': {'send': 1, 'wait': 3, 'receive': 1},
        }]}}
        self.assertTrue(self.origin.observed.empty())
        self.web('/flows/dump', method='POST', data=json.dumps(har).encode(), content_type='application/octet-stream')
        flows = json.loads(self.web('/flows'))
        self.assertEqual(len(flows), 1)
        self.assertTrue(self.origin.observed.empty(), 'Import must not contact the origin')
        flow_id = flows[0]['id']
        self.web(f'/flows/{flow_id}/replay', method='POST', data=b'')
        observed = self.origin.observed.get(timeout=8)
        self.assertEqual(observed['path'], '/from-har?a=1&a=2')
        self.assertEqual(observed['body'], payload)
        self.assertEqual(observed['duplicates'], ['one', 'two'])

    def test_websocket_text_and_binary_are_forwarded(self):
        port = self.origin.server_address[1]
        with socket.create_connection(('127.0.0.1', self.proxy_port), timeout=8) as sock:
            stream = sock.makefile('rb')
            sock.sendall((f'GET http://127.0.0.1:{port}/ws HTTP/1.1\r\n'
                          f'Host: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                          'Sec-WebSocket-Version: 13\r\n'
                          'Sec-WebSocket-Key: c3ludGhldGljLWtleS0xMg==\r\n\r\n').encode())
            self.assertIn(b'101', stream.readline())
            while stream.readline() != b'\r\n':
                pass
            for opcode, payload in ((1, b'hello relay'), (2, b'\x00\xff\x80'), (8, b'\x03\xe8')):
                mask = b'\x11\x22\x33\x44'
                masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
                sock.sendall(bytes([128 | opcode, 128 | len(payload)]) + mask + masked)
                returned_opcode, returned = read_frame(stream)
                self.assertEqual((returned_opcode, returned), (opcode, payload))
            stream.close()

    def test_http2_har_without_length_replays_with_correct_http1_body_framing(self):
        payload = b'{"test":"synthetic"}'
        port = self.tls_origin.server_address[1]
        path = '/h2-replay?first=1&first=2'
        har = {'log': {'version': '1.2', 'entries': [{
            'startedDateTime': '2026-10-27T10:00:00Z', 'time': 1,
            'request': {'method': 'POST', 'url': f'https://127.0.0.1:{port}' + path,
                'httpVersion': 'h2', 'headers': [
                    {'name': ':method', 'value': 'POST'},
                    {'name': ':scheme', 'value': 'https'},
                    {'name': ':authority', 'value': f'127.0.0.1:{port}'},
                    {'name': ':path', 'value': path},
                    {'name': 'content-type', 'value': 'application/json'},
                ], 'bodySize': len(payload),
                'postData': {'mimeType': 'application/json', 'text': payload.decode()}},
            'response': {'status': 200, 'statusText': 'OK', 'httpVersion': 'h2',
                'headers': [], 'content': {'size': 3, 'mimeType': 'text/plain', 'text': 'old'},
                'bodySize': 3},
        }]}}
        self.web('/flows/dump', method='POST', data=json.dumps(har).encode(), content_type='application/octet-stream')
        flows = json.loads(self.web('/flows'))
        self.assertEqual(len(flows), 1)
        self.assertTrue(self.tls_origin.observed.empty())
        self.web('/flows/' + flows[0]['id'] + '/replay', method='POST', data=b'')
        observed = self.tls_origin.observed.get(timeout=8)
        self.assertEqual(observed['path'], path)
        self.assertEqual(observed['body'], payload)


if __name__ == '__main__':
    unittest.main()
