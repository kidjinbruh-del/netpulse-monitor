"""Desktop launcher: dependency check, single local server, browser."""
import argparse
import ctypes
import importlib.util
import json
import os
import socket
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import urllib.parse
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOGS = ROOT / 'logs'
MODULES = ('psutil', 'numpy', 'pandas', 'sklearn', 'fastapi', 'uvicorn',
           'websockets', 'msgpack', 'pydantic', 'yaml', 'watchdog', 'colorama')


def endpoint():
    path = ROOT / 'config.json'
    config = json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}
    port = config.get('web_port', 8770)
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError('Invalid web_port in config.json')
    if (config.get('web_tls') or {}).get('enabled'):
        raise ValueError('HTTPS is configured. Open the configured trusted HTTPS hostname; this launcher does not bypass certificate verification.')
    host = config.get('web_host', '127.0.0.1')
    if host not in ('127.0.0.1', 'localhost', '0.0.0.0', '::1', '::'):
        raise ValueError('Launcher supports a local web listener; check web_host in config.json')
    address = '[::1]' if host in ('::1', '::') else '127.0.0.1'
    return 'http://' + address + ':' + str(port)


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


def occupied(url):
    parts = urllib.parse.urlsplit(url)
    try:
        with socket.create_connection((parts.hostname, parts.port), timeout=1):
            return True
    except OSError:
        return False


def launch(open_browser=True):
    if sys.version_info < (3, 12):
        raise RuntimeError('Python 3.12 or newer is required')
    LOGS.mkdir(exist_ok=True)
    url = endpoint()
    if not health(url):
        if occupied(url):
            raise RuntimeError('The configured port is occupied by a different or unhealthy service. No process was stopped. Check logs/netpulse.log.')
        missing = [name for name in MODULES if importlib.util.find_spec(name) is None]
        flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        if missing:
            with (LOGS / 'setup.log').open('ab') as output:
                result = subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', str(ROOT / 'requirements.txt')],
                    cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, creationflags=flags,
                    timeout=600, env={**os.environ, 'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INPUT': '1'})
            if result.returncode:
                raise RuntimeError('Dependency installation failed. See logs/setup.log')
        with (LOGS / 'server.out.log').open('ab') as output, (LOGS / 'server.err.log').open('ab') as errors:
            process = subprocess.Popen([sys.executable, '-m', 'netpulse'], cwd=ROOT,
                stdin=subprocess.DEVNULL, stdout=output, stderr=errors, creationflags=flags,
                start_new_session=os.name != 'nt', env={**os.environ, 'NETPULSE_NO_BROWSER':'1'})
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if health(url):
                break
            if process.poll() is not None:
                raise RuntimeError('NetPulse stopped during startup. See logs/server.err.log and logs/netpulse.log')
            time.sleep(.5)
        else:
            raise RuntimeError('Startup is taking longer than expected. See logs/server.err.log; try the shortcut again later.')
    if open_browser:
        webbrowser.open(url + '/#operations', new=2)
    return url


def main():
    parser = argparse.ArgumentParser(description='Start NetPulse and open the local panel')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    # A named mutex prevents two double-clicks from starting duplicate processes.
    handle = None
    linux_lock = None
    if os.name == 'nt':
        import hashlib
        kernel = ctypes.windll.kernel32
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        kernel.CreateMutexW.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.ReleaseMutex.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        name = 'Local\\NetPulseLauncher-' + hashlib.sha256(str(ROOT).casefold().encode()).hexdigest()[:20]
        handle = kernel.CreateMutexW(None, False, name)
        if not handle:
            raise OSError('Could not create launcher lock')
        if kernel.WaitForSingleObject(handle, 1000) not in (0, 128):
            kernel.CloseHandle(handle)
            return
    else:
        import fcntl
        LOGS.mkdir(exist_ok=True)
        linux_lock = (LOGS / 'launcher.lock').open('a')
        try:
            fcntl.flock(linux_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            linux_lock.close()
            return
    try:
        url = launch(not args.no_browser)
        if sys.stdout:
            print(url)
    except Exception as error:
        LOGS.mkdir(exist_ok=True)
        with (LOGS / 'launcher.log').open('a', encoding='utf-8') as stream:
            stream.write(time.strftime('%Y-%m-%d %H:%M:%S ') + str(error) + '\n')
        if os.name == 'nt' and not args.no_browser:
            ctypes.windll.user32.MessageBoxW(None, str(error) + '\n\nLogs: ' + str(LOGS), 'NetPulse', 0x10)
        elif not args.no_browser and (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')) and shutil.which('zenity'):
            subprocess.Popen(['zenity','--error','--title=NetPulse',
                              '--text='+str(error)+'\n\nLogs: '+str(LOGS)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
        elif sys.stderr:
            print(str(error), file=sys.stderr)
        return 1
    finally:
        if handle:
            kernel.ReleaseMutex(handle)
            kernel.CloseHandle(handle)
        if linux_lock:
            linux_lock.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
