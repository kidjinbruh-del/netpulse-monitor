"""Read-only RouterOS transports. REST (v7) and API-SSL (v6/v7).

Only explicitly allowlisted print operations are exposed. TLS verification cannot
be disabled; use ca_file for a private router CA. Credentials stay in process env.
"""
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler


FIELDS = {
    'system/resource': ('uptime', 'version', 'board-name', 'cpu-load', 'free-memory', 'total-memory'),
    'system/identity': ('name',),
    'interface': ('name', 'type', 'running', 'disabled', 'rx-byte', 'tx-byte', 'rx-error', 'tx-error', 'rx-drop', 'tx-drop'),
}
TABLE_GROUPS = {
    'dhcp': 'ip/dhcp-server/lease', 'arp': 'ip/arp', 'addresses': 'ip/address',
    'vlan': 'interface/bridge/vlan', 'bridge_hosts': 'interface/bridge/host',
    'ppp': 'ppp/active', 'health': 'system/health',
    'wifi': 'interface/wifi/registration-table', 'wireless': 'interface/wireless/registration-table',
}
FIELDS.update({
    'ip/dhcp-server/lease': ('address','mac-address','host-name','status','server','expires-after'),
    'ip/arp': ('address','mac-address','interface','complete','dynamic'),
    'ip/address': ('address','network','interface','disabled'),
    'interface/bridge/vlan': ('bridge','vlan-ids','tagged','untagged','current-tagged','current-untagged'),
    'interface/bridge/host': ('mac-address','vid','on-interface','bridge','local','dynamic'),
    'ppp/active': ('name','service','address','uptime'),
    'system/health': ('name','value','type'),
    'interface/wifi/registration-table': ('interface','mac-address','signal','uptime','tx-rate','rx-rate'),
    'interface/wireless/registration-table': ('interface','mac-address','signal-strength','uptime','tx-rate','rx-rate'),
})
CORE_PATHS = ('system/resource', 'system/identity', 'interface')

MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 256


class RouterError(Exception):
    """Public, credential-free integration error."""


def validate_device(device):
    if not isinstance(device, dict):
        raise RouterError('Device must be an object')
    ident = device.get('id', '')
    if not isinstance(ident, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', ident):
        raise RouterError('Device id: 1..48 letters, digits, _ or -')
    transport = device.get('transport', 'rest')
    if transport not in ('rest', 'api_ssl'):
        raise RouterError('Transport must be rest or api_ssl')
    try:
        url = urlsplit(device.get('url', ''))
    except (TypeError, ValueError):
        raise RouterError('Invalid device URL') from None
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in ('', '/')):
        raise RouterError('Use an HTTPS origin without credentials or path')
    try:
        port = url.port or (443 if transport == 'rest' else 8729)
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError as error:
        raise RouterError('Invalid device port') from error
    username = device.get('username', '')
    env = device.get('password_env', '')
    if not isinstance(username, str) or not username or ':' in username or len(username) > 128:
        raise RouterError('A username without colons is required')
    if not isinstance(env, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', env):
        raise RouterError('password_env must reference an environment variable')
    try:
        timeout = float(device.get('timeout_sec', 5))
        if not 1 <= timeout <= 10:
            raise ValueError()
    except (TypeError, ValueError):
        raise RouterError('timeout_sec must be 1..10')
    tables = device.get('tables', [])
    if not isinstance(tables, list) or len(tables) > len(TABLE_GROUPS) or any(not isinstance(t, str) or t not in TABLE_GROUPS for t in tables):
        raise RouterError('Unknown optional table group')
    return url, port, timeout


def credentials(device):
    value = os.environ.get(device['password_env'])
    if not value:
        raise RouterError('Password environment variable is missing')
    return device['username'], value


def tls_context(device):
    return ssl.create_default_context(cafile=device.get('ca_file') or None)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RouterError('Router redirects are not permitted')


class RestClient:
    def __init__(self, device):
        self.device = device
        self.url, _, self.timeout = validate_device(device)
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=tls_context(device)), NoRedirect())

    def read(self, path):
        if path not in FIELDS:
            raise RouterError('Read operation not allowed')
        username, password = credentials(self.device)
        token = base64.b64encode(f'{username}:{password}'.encode()).decode('ascii')
        query = urlencode({'.proplist': ','.join(FIELDS[path])})
        headers = {'Authorization': 'Basic ' + token, 'Accept': 'application/json'}
        if path == 'interface':
            # Fixed read-only CLI print, needed for interface counters.
            headers['Content-Type'] = 'application/json'
            request = Request(self.device['url'].rstrip('/') + '/rest/interface/print',
                data=json.dumps({'.proplist': ','.join(FIELDS[path]), 'stats': ''}).encode(),
                headers=headers, method='POST')
        else:
            request = Request(self.device['url'].rstrip('/') + '/rest/' + path + '?' + query,
                              headers=headers, method='GET')
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise RouterError('Router response exceeds 2 MiB')
            rows = json.loads(raw)
            if not isinstance(rows, list) or len(rows) > MAX_ROWS or any(not isinstance(row, dict) for row in rows):
                raise RouterError('Invalid router response or too many interfaces')
            return rows
        except HTTPError as error:
            raise RouterError({401: 'Router authentication failed', 403: 'Router read permission denied',
                               404: 'REST unavailable; use API-SSL for RouterOS 6'}.get(error.code, 'Router HTTP error')) from None
        except (URLError, OSError):
            raise RouterError('Router unreachable or TLS verification failed') from None
        except (ValueError, UnicodeError):
            raise RouterError('Invalid router JSON response') from None


def encode_length(length):
    if not 0 <= length <= MAX_BYTES:
        raise RouterError('API word too large')
    if length < 0x80:
        return bytes([length])
    if length < 0x4000:
        return (length | 0x8000).to_bytes(2, 'big')
    if length < 0x200000:
        return (length | 0xC00000).to_bytes(3, 'big')
    return (length | 0xE0000000).to_bytes(4, 'big')


class ApiSSLClient:
    def __init__(self, device):
        self.device = device
        self.url, self.port, self.timeout = validate_device(device)
        self.sock = None
        self.deadline = 0

    def _recv(self, size):
        data = bytearray()
        while len(data) < size:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise RouterError('API operation timed out')
            self.sock.settimeout(min(self.timeout, left))
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise RouterError('Router closed API connection')
            data.extend(chunk)
        return bytes(data)

    def _length(self):
        first = self._recv(1)[0]
        if first < 0x80:
            return first
        if first < 0xC0:
            return ((first & 0x3F) << 8) | int.from_bytes(self._recv(1), 'big')
        if first < 0xE0:
            return ((first & 0x1F) << 16) | int.from_bytes(self._recv(2), 'big')
        if first < 0xF0:
            return ((first & 0x0F) << 24) | int.from_bytes(self._recv(3), 'big')
        if first == 0xF0:
            return int.from_bytes(self._recv(4), 'big')
        raise RouterError('Unsupported API control byte')

    def _exchange(self, words):
        self.deadline = time.monotonic() + self.timeout
        data = b''.join(encode_length(len(word.encode())) + word.encode() for word in words) + b'\0'
        self.sock.settimeout(self.timeout)
        self.sock.sendall(data)
        rows, sentence, total, word_count = [], [], 0, 0
        denied = False
        while True:
            size = self._length()
            total += size
            word_count += 1
            if size > MAX_BYTES or total > MAX_BYTES or word_count > 16384:
                raise RouterError('API response limit exceeded')
            if size:
                sentence.append(self._recv(size).decode('utf-8'))
                continue
            if not sentence:
                continue
            kind = sentence[0]
            attrs = dict(word[1:].split('=', 1) for word in sentence[1:] if word.startswith('=') and '=' in word[1:])
            if kind == '!fatal':
                raise RouterError('API connection rejected')
            if kind == '!trap':
                denied = True
            if kind == '!done':
                if denied:
                    raise RouterError('API request denied; check permissions and RouterOS support')
                return rows, attrs
            if kind == '!re':
                rows.append(attrs)
                if len(rows) > MAX_ROWS:
                    raise RouterError('Too many router interfaces')
            sentence = []

    def __enter__(self):
        username, password = credentials(self.device)
        raw = None
        try:
            raw = socket.create_connection((self.url.hostname, self.port), timeout=self.timeout)
            self.sock = tls_context(self.device).wrap_socket(raw, server_hostname=self.url.hostname)
            if self.device.get('legacy_login', False):
                _, answer = self._exchange(['/login'])
                challenge = bytes.fromhex(answer.get('ret', ''))
                if len(challenge) != 16:
                    raise RouterError('Invalid legacy API challenge')
                response = '00' + hashlib.md5(b'\0' + password.encode() + challenge).hexdigest()
                self._exchange(['/login', '=name=' + username, '=response=' + response])
            else:
                self._exchange(['/login', '=name=' + username, '=password=' + password])
            return self
        except Exception:
            if self.sock:
                self.sock.close()
            elif raw:
                raw.close()
            raise RouterError('API-SSL connection or login failed; check CA, service and login mode') from None

    def read(self, path):
        if path not in FIELDS:
            raise RouterError('Read operation not allowed')
        try:
            words = ['/' + path + '/print', '=.proplist=' + ','.join(FIELDS[path])]
            if path == 'interface':
                words.append('=stats=')
            return self._exchange(words)[0]
        except (OSError, UnicodeError):
            raise RouterError('API-SSL transport failed') from None

    def __exit__(self, *args):
        if self.sock:
            self.sock.close()


def collect(device):
    def read(client):
        result = {path: client.read(path) for path in CORE_PATHS}
        errors = {}
        for group in dict.fromkeys(device.get('tables', [])):
            path = TABLE_GROUPS[group]
            try:
                result[path] = client.read(path)
            except RouterError as error:
                errors[path] = str(error)
        result['_table_errors'] = errors
        return result
    if device.get('transport', 'rest') == 'rest':
        return read(RestClient(device))
    with ApiSSLClient(device) as client:
        return read(client)
