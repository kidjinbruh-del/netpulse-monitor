"""Scheduled-task entry: elevate the known NetPulse instance, never arbitrary port owners."""
import ctypes
import argparse
import os
import sys
import time
from pathlib import Path
import psutil
from launch_netpulse import ROOT, endpoint, health, launch
from urllib.parse import urlsplit


def elevated(pid=None):
    if os.name != 'nt': return False
    if pid is None: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    from ctypes import wintypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    advapi=ctypes.WinDLL('advapi32',use_last_error=True)
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    process=kernel.OpenProcess(0x1000,False,pid)
    if not process: raise OSError('Cannot inspect existing server process')
    token=wintypes.HANDLE()
    try:
        if not advapi.OpenProcessToken(process,8,ctypes.byref(token)):raise OSError('Cannot inspect server token')
        value=wintypes.DWORD();size=wintypes.DWORD()
        if not advapi.GetTokenInformation(token,20,ctypes.byref(value),ctypes.sizeof(value),ctypes.byref(size)):raise OSError('Cannot read elevation state')
        return bool(value.value)
    finally:
        if token:kernel.CloseHandle(token)
        kernel.CloseHandle(process)


def main(restart=False):
    if not elevated(): raise RuntimeError('Administrator privileges are required; run the registered NetPulse task')
    url=endpoint();parts=urlsplit(url)
    if health(url):
        owners={conn.pid for conn in psutil.net_connections(kind='tcp') if conn.laddr and conn.laddr.port==parts.port and conn.status=='LISTEN' and conn.pid}
        for pid in owners:
            process=psutil.Process(pid)
            if Path(process.cwd()).resolve()!=ROOT or process.cmdline()[1:]!=['-m','netpulse']:
                raise RuntimeError('Existing listener is not the NetPulse instance in this checkout; no process stopped')
            if restart or not elevated(pid):
                process.terminate();process.wait(timeout=10)
                time.sleep(.5)
    launch(open_browser=False)
    return 0


if __name__=='__main__':
    parser=argparse.ArgumentParser(description='NetPulse administrator task entry')
    parser.add_argument('--restart',action='store_true',help='Restart only the verified NetPulse instance in this checkout')
    args=parser.parse_args()
    try: raise SystemExit(main(restart=args.restart))
    except Exception as error:
        (ROOT/'logs').mkdir(exist_ok=True)
        with (ROOT/'logs'/'admin-launcher.log').open('a',encoding='utf-8') as stream:stream.write(str(error)+'\n')
        raise
