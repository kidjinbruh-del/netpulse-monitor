"""LAN-сканер (Angry IP идея) + сканер портов (Nmap-lite).

v3-реализация: те же контракты LANNetworkScanner/PortScanner, типизировано.
scanner.service обязан давать .db/.cfg; опционально .push_alert.
"""
from __future__ import annotations

import logging
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from core.utils import decode_process_output

logger = logging.getLogger(__name__)

OUI_VENDORS = {
    "00:1A:11": "Google", "00:50:56": "VMware", "00:0C:29": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi", "00:1B:63": "Apple",
    "AC:DE:48": "Apple", "F0:18:98": "Apple", "A4:83:E7": "Apple",
    "D8:96:95": "ASUS", "04:D9:F5": "ASUS", "00:17:88": "Philips Hue",
    "44:47:CC": "Samsung", "00:E0:4C": "Realtek", "52:54:4C": "Xiaomi",
    "64:09:80": "Xiaomi", "78:11:DC": "Xiaomi", "18:B4:30": "TP-Link",
    "50:C7:BF": "TP-Link", "00:1D:7E": "Cisco", "00:23:04": "Huawei",
    "34:6B:D3": "Huawei", "D0:17:C2": "Pure Life", "00:15:5D": "Microsoft Hyper-V",
}

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 6379, 8080, 8443, 8888, 9200, 27017, 32400,
    5000, 53, 123, 161,
]
PORT_NAMES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
              80: "http", 110: "pop3", 143: "imap", 443: "https",
              445: "smb", 3389: "rdp", 3306: "mysql", 5900: "vnc",
              6379: "redis", 8080: "http-alt", 8443: "https-alt",
              27017: "mongodb", 32400: "plex", 123: "ntp", 161: "snmp"}

PING_TIMEOUT_MS = 250
PROBE_THREADS = 60
SCAN_JOIN_TIMEOUT = 6


def _now_iso() -> str:
    return datetime.now().isoformat()


class LANNetworkScanner:
    def __init__(self, service: Any):
        self.svc = service
        self.scanning = False
        self.last_result: List[Dict[str, Any]] = []
        self.known_macs: set = set()
        self._load_known()

    def _load_known(self) -> None:
        try:
            rows = self.svc.db.execute(
                "SELECT mac FROM lan_devices", fetch=True) or []
            self.known_macs = {(r["mac"] or "").lower() for r in rows}
        except Exception:
            self.known_macs = set()

    @staticmethod
    def local_subnet() -> tuple:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
        except Exception:
            ip = "192.168.1.1"
        finally:
            sock.close()
        parts = ip.split(".")
        return ".".join(parts[:3]) + ".", ip

    def auto_loop(self, interval_min: int) -> None:
        """Периодический автоскан подсети: новые ПК попадают в базу сами."""
        while not self.svc._stop_event.is_set():
            try:
                self.scan()
            except Exception as e:
                logger.info("[lan] auto-scan: %s", e)
            self.svc._stop_event.wait(max(60, int(interval_min) * 60))

    def arp_table(self) -> Dict[str, str]:
        table = {}
        try:
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            out = subprocess.run(["arp", "-a"], capture_output=True, timeout=6,
                                 creationflags=flags)
            text = decode_process_output(out.stdout)
            for line in text.splitlines():
                m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b.*?"
                              r"([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})", line)
                if m:
                    table[m.group(1)] = m.group(2).lower().replace("-", ":")
        except Exception:
            pass
        return table

    @staticmethod
    def _probe(last_octet: int, base: str, results: list) -> None:
        ip = f"{base}{last_octet}"
        cmd = (["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip]
               if sys.platform == "win32"
               else ["ping", "-c", "1", "-W", "1", ip])
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=2,
                                    creationflags=flags)
            txt = decode_process_output(result.stdout)
            if re.search(r"[=<]\s*\d+\s*(?:мс|ms)", txt, re.IGNORECASE) \
                    or result.returncode == 0 and "TTL" in txt.upper():
                results.append(ip)
        except Exception:
            pass

    def scan(
        self, progress_cb: Optional[Callable] = None
    ) -> List[Dict[str, Any]]:
        if self.scanning:
            return self.last_result
        self.scanning = True
        try:
            return self._scan_inner()
        finally:
            self.scanning = False

    def _scan_inner(self) -> List[Dict[str, Any]]:
        base, my_ip = self.local_subnet()
        results: List[str] = []
        sem = threading.Semaphore(PROBE_THREADS)

        def wrapped(n: int) -> None:
            with sem:
                self._probe(n, base, results)

        threads = []
        for n in range(1, 255):
            t = threading.Thread(target=wrapped, args=(n,), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=SCAN_JOIN_TIMEOUT)

        arp = self.arp_table()
        devices = []
        for ip in sorted(results, key=lambda x: tuple(map(int, x.split(".")))):
            hostname = self._resolve_name(ip)
            mac = arp.get(ip, "")
            if not mac and ip == my_ip:
                mac = self._self_mac(ip)
            vendor = next((v for pref, v in OUI_VENDORS.items()
                           if mac.startswith(pref.lower())), "")
            is_new = bool(mac) and mac not in self.known_macs
            dev = {"ip": ip, "mac": mac or "-", "hostname": hostname,
                   "vendor": vendor or ("—" if mac else ""),
                   "is_me": ip == my_ip, "is_new": is_new}
            devices.append(dev)
            if mac:
                self._persist_device(dev, is_new)

        self.last_result = devices
        return devices

    @staticmethod
    def _resolve_name(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "-"

    @staticmethod
    def _self_mac(ip: str) -> str:
        try:
            import psutil
            for _if_name, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == psutil.AF_LINK and a.address:
                        if_ip = next(
                            (x.address for x in addrs
                             if x.family == socket.AF_INET
                             and not x.address.startswith("169.")), "")
                        if if_ip == ip:
                            return a.address
        except Exception:
            pass
        return ""

    def _persist_device(self, dev: Dict[str, Any], is_new: bool) -> None:
        try:
            self.svc.db.execute(
                """INSERT INTO lan_devices (mac, ip, hostname, vendor, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(mac) DO UPDATE SET
                     ip=excluded.ip, hostname=excluded.hostname,
                     last_seen=excluded.last_seen""",
                (dev["mac"], dev["ip"], dev["hostname"], dev["vendor"],
                 _now_iso(), _now_iso()))
            if is_new:
                trusted = (self.svc.cfg.get("lan", {}) or {}).get(
                    "trusted_macs") or []
                if dev["mac"] not in {str(t).lower() for t in trusted}:
                    try:
                        self.svc.push_alert(
                            "LAN_NEW_DEVICE",
                            f"Новое устройство в сети: {dev['ip']} "
                            f"({dev['mac']}) {dev['vendor']}".strip(),
                            "lan")
                    except Exception:
                        pass
                    self.known_macs.add(dev["mac"])
        except Exception:
            pass

    def devices_from_db(self, limit: int = 200) -> List[Dict[str, Any]]:
        try:
            return self.svc.db.execute(
                """SELECT mac, ip, hostname, vendor, first_seen, last_seen,
                          alias
                   FROM lan_devices ORDER BY last_seen DESC LIMIT ?""",
                (limit,), fetch=True) or []
        except Exception:
            return []


class PortScanner:
    @staticmethod
    def tcp_scan(
        host: str, ports: Optional[List[int]] = None,
        timeout: float = 0.6, workers: int = 200,
    ) -> Dict[str, Any]:
        ports = ports or COMMON_PORTS
        open_ports: List[Dict[str, Any]] = []
        lock = threading.Lock()
        sem = threading.Semaphore(workers)

        def check(port: int) -> None:
            with sem:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    if sock.connect_ex((host, port)) == 0:
                        with lock:
                            open_ports.append({
                                "port": port,
                                "service": PORT_NAMES.get(port, "")})
                    sock.close()
                except Exception:
                    pass

        threads = [threading.Thread(target=check, args=(p,), daemon=True)
                   for p in dict.fromkeys(ports)]
        batch = 256
        for i in range(0, len(threads), batch):
            chunk = threads[i:i + batch]
            for t in chunk:
                t.start()
            for t in chunk:
                t.join(timeout=timeout + 2)

        open_ports.sort(key=lambda x: x["port"])
        return {"host": host, "scanned": len(set(ports)),
                "open": open_ports}
