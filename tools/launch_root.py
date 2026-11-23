#!/usr/bin/env python3
"""Desktop launcher for NetPulse running as root via pkexec.

Checks whether the systemd service is already running on the configured
port; if not, starts it (the service auto-restarts on failure). Opens the
local panel in a browser. Requires polkit passwordless escalation for
meow (pkexec).
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICE = 'netpulse-desktop'


def endpoint():
    path = ROOT / 'config.json'
    config = json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}
    port = config.get('web_port', 8770)
    host = config.get('web_host', '127.0.0.1')
    address = '127.0.0.1' if host in ('::1', '::') else host
    return f'http://{address}:{port}'


def health(url):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url + '/healthz', timeout=2) as response:
            payload = json.loads(response.read(8192))
        if payload.get('status') != 'ok':
            return False
        with opener.open(url + '/', timeout=2) as response:
            shell = response.read(4096)
        return b'<title>NetPulse</title>' in shell
    except (OSError, ValueError, urllib.error.URLError):
        return False


def service_running():
    try:
        result = subprocess.run(['systemctl', 'is-active', SERVICE],
                                capture_output=True, text=True, timeout=10)
        return result.stdout.strip() == 'active'
    except Exception:
        return False


def main():
    url = endpoint()
    if not health(url):
        if not service_running():
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
            subprocess.run(['systemctl', 'start', SERVICE], capture_output=True)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if health(url):
                break
            time.sleep(.5)
    webbrowser.open(url + '/#operations', new=2)
    print(url)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())