"""
Сервисы мониторинга NetPulse.

MonitorService - единый источник живого состояния:
- трафик суммарно и по интерфейсам (psutil)
- пинг-монитор + интегральное качество связи
- пер-процессная сетевая активность, события новых соединений
- IDS: детект сканов портов и подозрительных подключений
- квоты трафика (день/месяц), системные метрики
- AI-анализ тиков с прогнозом (numpy) и объяснением аномалий (z-score)
- запись истории в SQLite
"""

import json
import time
import socket
import struct
import threading
import subprocess
import sys
import re
import uuid
from collections import deque, defaultdict
from datetime import datetime

import psutil

from core import DatabaseManager, Pinger, SecurityScanner
from ai import AIOrchestrator

from .journal import WorkJournal
from .inventory import Inventory
from .watchdog import ParkWatchdog
from .runbooks import RunbookRunner
from .backupwatch import BackupWatch
from .planner import Planner
from .softwareinv import SoftwareInventory
from .infra import Infra
from .healing import Healing
from .customchecks import CustomChecks
from .l2map import L2Map
from .geo import country as geo_country, top_countries, flag as geo_flag
from .cve import CVEChecker
from .proxmox import ProxmoxClient
import logging

logger = logging.getLogger(__name__)

def _now_iso():
    return datetime.now().isoformat()


def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def quality_score(ping_ms, jitter_ms, loss_pct, q):
    """Интегральная оценка качества 0..100"""
    score = 100.0
    if ping_ms is not None and ping_ms > 0:
        if ping_ms <= q.get("good_ping_ms", 50):
            pass
        elif ping_ms <= q.get("warn_ping_ms", 120):
            score -= (ping_ms - q["good_ping_ms"]) / (q["warn_ping_ms"] - q["good_ping_ms"]) * 25
        else:
            score -= 25 + min(35, (ping_ms - q["warn_ping_ms"]) / 10 * 2)
    if jitter_ms and jitter_ms > 0:
        score -= min(20, jitter_ms / max(1, q.get("max_jitter_ms", 15)) * 12)
    if loss_pct and loss_pct > 0:
        score -= min(40, loss_pct / max(0.5, q.get("max_loss_pct", 2)) * 18)
    return round(max(0.0, min(100.0, score)), 1)


def quality_label(score):
    if score >= 85:
        return "Отлично", "#22d3a7"
    if score >= 65:
        return "Нормально", "#8bd450"
    if score >= 40:
        return "Проблемы", "#f5b942"
    return "Плохо", "#ff5c74"


# ================= Пер-процессный монитор + IDS =================

class ProcessMonitor:
    """Активность процессов в сети: соединения, новые эндпоинты, I/O-прокси.
    IDS: детект скана портов одним IP и стука на подозрительные порты."""

    def __init__(self, service):
        self.svc = service
        self._lock = threading.RLock()
        self._seen_endpoints = {}          # (pid, ip:port) -> ts
        self._scan_window = defaultdict(set)   # rip -> set(port)
        self._last_alert = defaultdict(float)  # rate-limit ключей
        self._io_last = {}                 # pid -> io bytes total
        self.processes = {}                # pid -> {"name","conns","est","io_kbps"}
        self.new_events = deque(maxlen=150)
        self.ids_events = deque(maxlen=150)

    def sample(self):
        try:
            raw = psutil.net_connections(kind="inet")
        except Exception:
            return

        pid_names = {}
        for p in psutil.process_iter(["pid", "name"]):
            try:
                pid_names[p.info["pid"]] = p.info["name"] or "?"
            except Exception:
                pass

        now = time.time()
        window = float(self.svc.cfg.get("ids", {}).get("window_sec", 120))
        suspicious_ports = set(self.svc.cfg.get("security", {}).get("suspicious_ports", []))
        scan_threshold = int(self.svc.cfg.get("security", {}).get("scan_detection_threshold", 15))
        ids_on = bool(self.svc.cfg.get("ids", {}).get("enabled", True))

        per_pid = defaultdict(lambda: {"conns": 0, "est": 0})
        seen_now = {}
        events = []

        for c in raw:
            pid = c.pid or 0
            per_pid[pid]["conns"] += 1
            if c.status == "ESTABLISHED":
                per_pid[pid]["est"] += 1
            if not c.raddr:
                continue
            key = (pid, f"{c.raddr.ip}:{c.raddr.port}")
            seen_now[key] = now

            if key not in self._seen_endpoints and c.status in ("ESTABLISHED", "SYN_SENT"):
                pname = pid_names.get(pid, "?")
                events.append({
                    "ts": now, "pid": pid, "process": pname,
                    "remote": f"{c.raddr.ip}:{c.raddr.port}",
                    "local_port": c.laddr.port if c.laddr else 0,
                    "suspicious": c.raddr.port in suspicious_ports,
                })
                if ids_on and not c.raddr.ip.startswith(("127.", "::1")):
                    self._scan_window[c.raddr.ip].add(c.raddr.port)
                    if len(self._scan_window[c.raddr.ip]) >= scan_threshold:
                        self._raise_ids(
                            "PORT_SCAN",
                            f"Скан портов с {c.raddr.ip}: "
                            f"{len(self._scan_window[c.raddr.ip])} разных целей за {window:.0f}с")
                        self._scan_window[c.raddr.ip].clear()
                    if c.raddr.port in suspicious_ports:
                        # whitelist IDS: {"process": "mstsc.exe", "ports": "3389"}
                        wl = self.svc.cfg.get("ids", {}).get("whitelist") or []
                        wl_hit = False
                        for rule in wl:
                            if not isinstance(rule, dict):
                                continue
                            proc_ok = (not rule.get("process")
                                       or str(rule["process"]).lower()
                                       in str(pname).lower())
                            ports_ok = True
                            if rule.get("ports"):
                                try:
                                    ports_ok = int(c.raddr.port) in [
                                        int(x) for x in
                                        str(rule["ports"]).replace(" ", "").split(",")
                                        if x]
                                except (ValueError, TypeError):
                                    ports_ok = True
                            if proc_ok and ports_ok:
                                wl_hit = True
                                break
                        if wl_hit:
                            continue
                        rl_key = f"sus:{c.raddr.ip}:{c.raddr.port}"
                        if now - self._last_alert[rl_key] > 300:
                            self._last_alert[rl_key] = now
                            self._raise_ids(
                                "SUSPICIOUS_CONN",
                                f"{pname} (PID {pid}) подключился к подозрительному порту "
                                f"{c.raddr.ip}:{c.raddr.port}")

        # чистка окон
        cutoff = now - max(window * 3, 300)
        self._seen_endpoints = {k: v for k, v in self._seen_endpoints.items() if v > cutoff}
        self._seen_endpoints.update(seen_now)

        # I/O прокси по процессам (дельта суммарных IO-байтов)
        io_rates = {}
        alive_pids = set(per_pid.keys()) | set(self._io_last.keys())
        for pid in list(alive_pids)[:400]:
            try:
                io = psutil.Process(pid).io_counters()
                total = io.read_bytes + io.write_bytes
                last = self._io_last.get(pid)
                self._io_last[pid] = total
                if last is not None:
                    d = max(0, total - last)
                    if d > 512:
                        io_rates[pid] = d / 1024.0
            except Exception:
                self._io_last.pop(pid, None)

        with self._lock:
            self.processes = {
                pid: {
                    "pid": pid,
                    "name": pid_names.get(pid, "?"),
                    "conns": v["conns"],
                    "est": v["est"],
                    "io_kbps": round(io_rates.get(pid, 0), 1),
                }
                for pid, v in per_pid.items()
            }
            for e in reversed(events[-30:]):
                self.new_events.appendleft(e)

    def _raise_ids(self, alert_type, message):
        with self._lock:
            dup = any(e["type"] == alert_type and e["message"] == message
                      for e in list(self.ids_events)[-10:])
            self.ids_events.appendleft({"ts": time.time(), "type": alert_type,
                                        "message": message})
        if not dup:
            self.svc.push_alert(alert_type, message, "ids")

    def top_io(self, limit=15):
        with self._lock:
            procs = sorted(self.processes.values(),
                           key=lambda p: (-p["io_kbps"], -p["est"]))[:limit]
        return procs

    def new_connections(self, limit=80):
        with self._lock:
            return list(self.new_events)[:limit]

    def ids_feed(self, limit=80):
        with self._lock:
            return list(self.ids_events)[:limit]


# ================= Живой MTR (PingPlotter/WinMTR идея) =================

class MTREngine:
    def __init__(self, service):
        self.svc = service
        self.target = None
        self.hops = []          # [{"hop","ip","samples":deque[(ok,ms)]}]
        self.running = False
        self.cycles_done = 0
        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.RLock()

    def start(self, target=None, max_hops=None, cycle_sec=None, pings_per_hop=None):
        mcfg = self.svc.cfg.get("mtr", {})
        target = target or mcfg.get("target", "8.8.8.8")
        max_hops = int(max_hops or mcfg.get("max_hops", 12))
        cycle_sec = float(cycle_sec or mcfg.get("cycle_sec", 10))
        pings_per_hop = int(pings_per_hop or mcfg.get("pings_per_hop", 2))

        if self.running:
            self.stop()
        with self._lock:
            self.target = target
            self.hops = [{"hop": i, "ip": "?", "samples": deque(maxlen=90)}
                         for i in range(1, max_hops + 1)]
            self.cycles_done = 0
            self.running = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop,
                                        args=(target, max_hops, cycle_sec, pings_per_hop),
                                        daemon=True, name="np-mtr")
        self._thread.start()

    def stop(self):
        self.running = False
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=15)

    def _loop(self, target, max_hops, cycle_sec, pings_per_hop):
        from core.utils import decode_process_output, parse_trace_output, parse_ping_output
        while self.running and not self._stop.is_set():
            reached = False
            for hop_rec in self.hops[:max_hops]:
                if not self.running:
                    break
                ttl = hop_rec["hop"]
                cmd = (["ping", "-n", str(pings_per_hop), "-i", str(ttl),
                        "-w", "900", target] if sys.platform == "win32"
                       else ["ping", "-c", str(pings_per_hop), "-t", str(ttl), "-W", "1", target])
                try:
                    proc = subprocess.run(cmd, capture_output=True, timeout=pings_per_hop * 2 + 4,
                                          creationflags=subprocess.CREATE_NO_WINDOW
                                          if sys.platform == "win32" else 0)
                    out = decode_process_output(proc.stdout + proc.stderr)
                except Exception:
                    out = ""

                hop_ip, first_ms = parse_trace_output(out, target=target)
                if hop_ip != "*" and hop_ip != "?":
                    hop_rec["ip"] = hop_ip

                times = [float(t.replace(",", ".")) for t in _ms_times(out)]
                hop_answered = hop_ip not in ("*", "?")
                if times:
                    for msv in times:
                        hop_rec["samples"].append((True, msv))
                elif hop_answered:
                    # Хоп ответил «TTL превышен» без поля времени (Windows) —
                    # это ОТВЕТ, а не потеря; латентность промежуточного хопа
                    # так не измерить, но потери считаем честно
                    hop_rec["samples"].append((True, None))
                else:
                    hop_rec["samples"].append((False, None))

                if hop_ip == target:
                    reached = True
                    break

            with self._lock:
                self.cycles_done += 1
            self._stop.wait(cycle_sec if not reached else max(2, cycle_sec / 2))

    def stats(self):
        with self._lock:
            out = []
            for h in self.hops:
                samples = list(h["samples"])
                sent = len(samples)
                replies = [m for ok, m in samples if ok]
                oks = [m for ok, m in samples if ok and m is not None]
                loss = round(100 * (sent - len(replies)) / sent, 1) if sent else 0.0
                out.append({
                    "hop": h["hop"],
                    "ip": h["ip"] if h["ip"] != "?" else "*",
                    "sent": sent,
                    "loss_pct": loss,
                    "avg_ms": round(sum(oks) / len(oks), 1) if oks else None,
                    "min_ms": round(min(oks), 1) if oks else None,
                    "max_ms": round(max(oks), 1) if oks else None,
                    "graph": [round(m, 1) if m is not None else None
                              for _, m in samples[-60:]],
                })
            return {"running": self.running, "target": self.target,
                    "cycles": self.cycles_done, "hops": out}

    def save_snapshot(self):
        """Сохраняет последний цикл MTR в БД (история задержек)."""
        st = self.stats()
        if not st["hops"] or not self.svc:
            return
        try:
            self.svc.db.execute(
                """CREATE TABLE IF NOT EXISTS mtr_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL, target TEXT NOT NULL,
                    hop INTEGER, ip TEXT, loss_pct REAL, avg_ms REAL)""")
            now = datetime.now().isoformat()
            self.svc.db.execute_many(
                "INSERT INTO mtr_history (ts, target, hop, ip, loss_pct, avg_ms) "
                "VALUES (?,?,?,?,?,?)",
                [(now, st["target"], h["hop"], h["ip"], h["loss_pct"], h["avg_ms"])
                 for h in st["hops"]])
        except Exception as e:
            logger.debug("mtr snapshot: %s", e)

    def schedule_loop(self):
        """Веер целей: цикл по targets с ротацией каждые rotate_sec."""
        mcfg = self.svc.cfg.get("mtr", {}) or {}
        targets = list(mcfg.get("targets") or []) or [mcfg.get("target", "8.8.8.8")]
        rotate = int(mcfg.get("rotate_sec", 600) or 600)
        idx = 0
        while self.running and not self.svc._stop_event.is_set():
            tgt = targets[idx % len(targets)]
            self.start(target=tgt)
            waited = 0
            while self.running and waited < rotate:
                if self.svc._stop_event.wait(10):
                    return
                waited += 10
                if waited % 120 == 0:
                    self.save_snapshot()
            idx += 1


def _ms_times(output):
    import re as _re
    return _re.findall(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*(?:мс|ms)", output, _re.IGNORECASE)


# ================= LAN сканер (Angry IP идея) =================

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


class LANNetworkScanner:
    def __init__(self, service):
        self.svc = service
        self.scanning = False
        self.last_result = []
        self.known_macs = set()
        self._load_known()

    def _load_known(self):
        try:
            rows = self.svc.db.execute(
                "SELECT mac FROM lan_devices", fetch=True) or []
            self.known_macs = {(r["mac"] or "").lower() for r in rows}
        except Exception:
            self.known_macs = set()

    @staticmethod
    def local_subnet():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "192.168.1.1"
        finally:
            s.close()
        parts = ip.split(".")
        return ".".join(parts[:3]) + ".", ip

    def auto_loop(self, interval_min: int):
        """Периодический автоскан подсети: новые ПК попадают в базу сами."""
        while not self.svc._stop_event.is_set():
            try:
                self.scan()
            except Exception as e:
                logger.info(f"[lan] auto-scan: {e}")
            self.svc._stop_event.wait(max(60, int(interval_min) * 60))

    def arp_table(self):
        table = {}
        try:
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            out = subprocess.run(["arp", "-a"], capture_output=True, timeout=6,
                                 creationflags=flags)
            from core.utils import decode_process_output
            text = decode_process_output(out.stdout)
            for line in text.splitlines():
                m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b.*?"
                              r"([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})", line)
                if m:
                    table[m.group(1)] = m.group(2).lower().replace("-", ":")
        except Exception:
            pass
        return table

    def scan(self, progress_cb=None):
        if self.scanning:
            return self.last_result
        self.scanning = True
        base, my_ip = self.local_subnet()
        arp = {}

        def probe(last_octet, results):
            ip = f"{base}{last_octet}"
            cmd = (["ping", "-n", "1", "-w", "250", ip] if sys.platform == "win32"
                   else ["ping", "-c", "1", "-W", "1", ip])
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=2,
                                   creationflags=flags)
                from core.utils import decode_process_output
                txt = decode_process_output(r.stdout)
                if re.search(r"[=<]\s*\d+\s*(?:мс|ms)", txt, re.IGNORECASE) or r.returncode == 0 and "TTL" in txt.upper():
                    results.append(ip)
            except Exception:
                pass

        results = []
        threads = []
        sem = threading.Semaphore(60)

        def wrapped(n):
            with sem:
                probe(n, results)

        for n in range(1, 255):
            t = threading.Thread(target=wrapped, args=(n,), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=6)

        arp = self.arp_table()
        devices = []
        for ip in sorted(results, key=lambda x: tuple(map(int, x.split(".")))):
            hostname = "-"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
            mac = arp.get(ip, "")
            if not mac and ip == my_ip:
                try:
                    for if_name, addrs in psutil.net_if_addrs().items():
                        for a in addrs:
                            if a.family == psutil.AF_LINK and a.address:
                                if_ip = next(
                                    (x.address for x in addrs
                                     if x.family == socket.AF_INET
                                     and not x.address.startswith("169.")), "")
                                if if_ip == ip:
                                    mac = a.address
                except Exception:
                    pass
            vendor = next((v for pref, v in OUI_VENDORS.items()
                           if mac.startswith(pref.lower())), "")
            is_new = bool(mac) and mac not in self.known_macs
            dev = {"ip": ip, "mac": mac or "-", "hostname": hostname,
                   "vendor": vendor or ("—" if mac else ""),
                   "is_me": ip == my_ip, "is_new": is_new}
            devices.append(dev)
            if mac:
                try:
                    self.svc.db.execute(
                        """INSERT INTO lan_devices (mac, ip, hostname, vendor, first_seen, last_seen)
                           VALUES (?,?,?,?,?,?)
                           ON CONFLICT(mac) DO UPDATE SET
                             ip=excluded.ip, hostname=excluded.hostname,
                             last_seen=excluded.last_seen""",
                        (mac, ip, hostname, vendor, _now_iso(), _now_iso()))
                    trusted = (self.svc.cfg.get("lan", {}) or {}).get(
                        "trusted_macs") or []
                    if is_new and mac not in {str(t).lower() for t in trusted}:
                        self.svc.push_alert(
                            "LAN_NEW_DEVICE",
                            f"Новое устройство в сети: {ip} ({mac}) {vendor}".strip(),
                            "lan")
                        self.known_macs.add(mac)
                except Exception:
                    pass

        self.last_result = devices
        self.scanning = False
        return devices

    def devices_from_db(self, limit=200):
        try:
            return self.svc.db.execute(
                """SELECT mac, ip, hostname, vendor, first_seen, last_seen,
                          alias
                   FROM lan_devices ORDER BY last_seen DESC LIMIT ?""",
                (limit,), fetch=True) or []
        except Exception:
            return []


# ================= Сканер портов (Nmap-lite) =================

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


class PortScanner:
    @staticmethod
    def tcp_scan(host, ports=None, timeout=0.6, workers=200):
        ports = ports or COMMON_PORTS
        open_ports = []
        lock = threading.Lock()
        sem = threading.Semaphore(workers)

        def check(port):
            with sem:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    if s.connect_ex((host, port)) == 0:
                        with lock:
                            open_ports.append({
                                "port": port,
                                "service": PORT_NAMES.get(port, "")})
                    s.close()
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


# ================= Захват пакетов (Wireshark-идея, stdlib raw socket) =================

class RawCaptureService:
    PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 2: "IGMP"}

    def __init__(self, service):
        self.svc = service
        self.running = False
        self.packets = deque(maxlen=600)
        self.stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "bytes": 0}
        self._sock = None
        self._thread = None
        self._stop = threading.Event()

    @staticmethod
    def available():
        return _is_admin()

    def start(self, filter_proto=None):
        if self.running:
            return {"ok": False, "error": "уже запущен"}
        if not self.available():
            return {"ok": False,
                    "error": "нужны права администратора для захвата пакетов"}

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            host_ip = self._default_local_ip()
            s.bind((host_ip, 0))
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            s.settimeout(1)
            self._sock = s
        except Exception as e:
            return {"ok": False, "error": f"raw socket: {e}"}

        self.packets.clear()
        for k in self.stats:
            self.stats[k] = 0
        self._filter_proto = (filter_proto or "").upper()
        self._stop.clear()
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="np-capture")
        self._thread.start()
        return {"ok": True}

    @staticmethod
    def _default_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
        finally:
            s.close()

    def stop(self):
        self.running = False
        self._stop.set()
        try:
            if self._sock:
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self._sock.close()
        except Exception:
            pass
        self._sock = None

    def _loop(self):
        while self.running and not self._stop.is_set():
            try:
                data = self._sock.recv(65535)
                if len(data) < 20:
                    continue
                ver_ihl = data[0]
                if ver_ihl >> 4 != 4:
                    continue
                ihl = (ver_ihl & 0xF) * 4
                proto = data[9]
                src = socket.inet_ntoa(data[12:16])
                dst = socket.inet_ntoa(data[16:20])
                length = struct.unpack("!H", data[2:4])[0]

                pname = self.PROTO_NAMES.get(proto, f"IP-{proto}")
                if self._filter_proto and pname != self._filter_proto:
                    continue

                info = ""
                if proto == 6 and len(data) >= ihl + 4:
                    sport, dport = struct.unpack("!HH", data[ihl:ihl + 4])
                    info = f"{sport} → {dport}"
                elif proto == 17 and len(data) >= ihl + 4:
                    sport, dport = struct.unpack("!HH", data[ihl:ihl + 4])
                    info = f"{sport} → {dport}"

                self.packets.appendleft({
                    "ts": time.time(), "src": src, "dst": dst,
                    "proto": pname, "len": length, "info": info})
                self.stats["total"] += 1
                self.stats["bytes"] += length
                key = pname.lower() if pname in ("TCP", "UDP", "ICMP") else "other"
                self.stats[key] = self.stats.get(key, 0) + 1
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                continue

    def snapshot(self, limit=120):
        return {"running": self.running, "available": self.available(),
                "stats": dict(self.stats),
                "packets": list(self.packets)[:limit]}


# ================= Квоты трафика (NetWorx идея) =================

class QuotaManager:
    def __init__(self, service):
        self.svc = service
        self._cache = {"ts": 0, "data": None}

    def usage(self):
        now = time.time()
        if self._cache["data"] and now - self._cache["ts"] < 60:
            return self._cache["data"]

        day = self.svc.db.execute(
            """SELECT SUM(bytes_in_delta + bytes_out_delta) AS b FROM traffic
               WHERE timestamp > datetime('now','localtime','start of day')""",
            fetch=True)
        month = self.svc.db.execute(
            """SELECT SUM(bytes_in_delta + bytes_out_delta) AS b FROM traffic
               WHERE timestamp > datetime('now','localtime','start of month')""",
            fetch=True)

        q = self.svc.cfg.get("quota", {})
        daily_used_mb = ((day[0]["b"] or 0) if day else 0) / 1048576
        monthly_used_gb = (((month[0]["b"] or 0) if month else 0) / 1073741824)

        daily_limit = float(q.get("daily_mb") or 0)
        monthly_limit = float(q.get("monthly_gb") or 0)

        data = {
            "daily_used_mb": round(daily_used_mb, 1),
            "daily_limit_mb": daily_limit,
            "daily_pct": round(100 * daily_used_mb / daily_limit, 1) if daily_limit else None,
            "monthly_used_gb": round(monthly_used_gb, 3),
            "monthly_limit_gb": monthly_limit,
            "monthly_pct": round(100 * monthly_used_gb / monthly_limit, 1) if monthly_limit else None,
        }
        warn = float(q.get("warn_pct", 80))

        if daily_limit and data["daily_pct"] >= 100:
            self.svc.push_alert("QUOTA_DAY", "Дневной лимит трафика исчерпан!", "quota", rate=3600)
        elif daily_limit and data["daily_pct"] >= warn:
            self.svc.push_alert("QUOTA_DAY", f"Использовано {data['daily_pct']}% дневного лимита", "quota", rate=3600)

        if monthly_limit and data["monthly_pct"] >= 100:
            self.svc.push_alert("QUOTA_MONTH", "Месячный лимит трафика исчерпан!", "quota", rate=21600)
        elif monthly_limit and data["monthly_pct"] >= warn:
            self.svc.push_alert("QUOTA_MONTH", f"Использовано {data['monthly_pct']}% месячного лимита", "quota", rate=21600)

        self._cache = {"ts": now, "data": data}
        return data


# ================= Основной сервис =================

class MonitorService:
    def __init__(self, config):
        self.cfg = config
        self.db = DatabaseManager()
        self.started_at = time.time()

        self._ensure_tables()

        self.pinger = Pinger(
            target=config.get("ping_target", "8.8.8.8"),
            alert_thresholds=self._alert_thresholds(),
            alert_callback=lambda t, m: self.push_alert(t, m, "pinger"),
        )
        self.pinger.set_db_callback(self._save_pings)

        ai_cfg = dict(config.get("ai", {}))
        self.ai = AIOrchestrator(
            config=ai_cfg,
            alert_callback=self._on_ai_alert,
            data_provider=self._training_provider,
        )

        self.procmon = ProcessMonitor(self)
        self.mtr = MTREngine(self)
        self.lan = LANNetworkScanner(self)
        self.capture = RawCaptureService(self)
        self.quota = QuotaManager(self)

        # Платформа отдела: журнал, парк, сторожа, кнопки
        self.journal = WorkJournal(self)
        self.inventory = Inventory(self)
        self.watchdog = ParkWatchdog(self)
        self.runbooks = RunbookRunner(self)
        self.backupwatch = BackupWatch(self)
        self.planner = Planner(self)
        self.softwareinv = SoftwareInventory(self)
        self.infra = Infra(self)
        self.healing = Healing(self)
        self.customchecks = CustomChecks(self)
        self.l2map = L2Map(self)
        self.cve = CVEChecker(self)
        self.proxmox = ProxmoxClient(self)

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._threads = []

        self._psutil_last = None
        self.history = deque(maxlen=1800)
        self._ram_hist = deque(maxlen=120)
        self.live_alerts = deque(maxlen=60)
        self._alert_rl = {}
        self._cached_state_json = "{}"
        self._cached_state_ts = 0

        self.snapshot = {
            "ts": time.time(),
            "down_kbps": 0.0, "up_kbps": 0.0, "total_kbps": 0.0,
            "total_down_mb": 0.0, "total_up_mb": 0.0, "max_kbps": 0.0,
            "pernic": {},
            "ping": {"current": None, "jitter": 0.0, "loss_pct": 0.0, "min": 0.0, "max": 0.0},
            "quality": {"score": 100.0, "label": "Отлично", "color": "#22d3a7"},
            "system": {"cpu": 0.0, "mem_pct": 0.0, "mem_used_gb": 0.0, "mem_total_gb": 0.0},
            "uptime_sec": 0,
            "mode": {"traffic": "psutil", "admin": False},
            "alerts_unread": 0,
        }
        self._tick = 0

    def _ensure_tables(self):
        try:
            self.db.execute("""CREATE TABLE IF NOT EXISTS lan_devices (
                mac TEXT PRIMARY KEY,
                ip TEXT, hostname TEXT, vendor TEXT,
                first_seen TEXT, last_seen TEXT)""")
            lcols = [r["name"] for r in (self.db.execute(
                "PRAGMA table_info(lan_devices)", fetch=True) or [])]
            if lcols and "alias" not in lcols:
                self.db.execute(
                    "ALTER TABLE lan_devices ADD COLUMN alias TEXT")
            self.db.execute("""CREATE TABLE IF NOT EXISTS speedtest_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                mbps REAL, direction TEXT DEFAULT 'down', bytes INTEGER)""")
            self.db.execute("""CREATE INDEX IF NOT EXISTS idx_speedtest_ts
                               ON speedtest_log(timestamp)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT, ip TEXT,
                action TEXT NOT NULL,
                status INTEGER,
                details TEXT)""")
            self.db.execute("""CREATE INDEX IF NOT EXISTS idx_audit_ts
                               ON audit_log(timestamp)""")
            # --- платформа отдела ---
            # свои таблицы модули создают сами (planner_state, sw_inventory,
            # миграция hosts — в Inventory.__init__)
        except Exception as e:
            logger.info(f"[db] таблицы NetPulse: {e}")

    # ---------- жизненный цикл ----------

    def start(self):
        self.pinger.start()
        if self.cfg.get("ai", {}).get("enabled", True):
            try:
                hist = self._training_provider()
                if hist and len(hist) >= 10:
                    self.ai.train_model(hist)
            except Exception as e:
                logger.info(f"[ai] стартовое обучение: {e}")
            self.ai.start_background_training()

        for name, target in (
            ("np-traffic", self._traffic_loop),
            ("np-tick", self._tick_loop),
            ("np-procmon", self._procmon_loop),
            ("np-cleanup", self._cleanup_loop),
        ):
            t = threading.Thread(target=target, daemon=True, name=name)
            t.start()
            self._threads.append(t)

        if self.cfg.get("watchdog", {}).get("enabled"):
            self.watchdog.start()
        if self.cfg.get("backupwatch", {}).get("enabled"):
            self.backupwatch.start()
        if self.cfg.get("planner", {}).get("enabled"):
            self.planner.start()

        auto_min = int((self.cfg.get("lan") or {}).get("auto_scan_min", 0) or 0)
        if auto_min > 0:
            t = threading.Thread(target=self.lan.auto_loop, args=(auto_min,),
                                 daemon=True, name="np-lanscan")
            t.start()
            self._threads.append(t)

            # L2-карта: редкий опрос портов коммутаторов после автоскана
            t = threading.Thread(target=self._l2_auto_loop, daemon=True,
                                 name="np-l2map")
            t.start()
            self._threads.append(t)

        if self.cfg.get("report", {}).get("weekly", {}).get("enabled"):
            t = threading.Thread(target=self._weekly_report_loop, daemon=True,
                                 name="np-weekly")
            t.start()
            self._threads.append(t)

        if self.cfg.get("escalate", {}).get("enabled"):
            t = threading.Thread(target=self._escalate_loop, daemon=True,
                                 name="np-escalate")
            t.start()
            self._threads.append(t)

        if (self.cfg.get("mtr") or {}).get("targets"):
            t = threading.Thread(target=self.mtr.schedule_loop, daemon=True,
                                 name="np-mtrfan")
            t.start()
            self._threads.append(t)

        if (self.cfg.get("proxmox") or {}).get("enabled"):
            t = threading.Thread(target=self.proxmox.loop, daemon=True,
                                 name="np-proxmox")
            t.start()
            self._threads.append(t)

        admin = _is_admin()
        with self._lock:
            self.snapshot["mode"]["admin"] = admin
        logger.info(f"[netpulse] мониторинг запущен (админ: {'да' if admin else 'нет'})")

    def stop(self):
        self._stop_event.set()
        for stopper in (lambda: self.pinger.stop(),
                        lambda: self.ai.stop(),
                        lambda: self.mtr.stop(),
                        lambda: self.capture.stop(),
                        lambda: self.watchdog.stop(),
                        lambda: self.backupwatch.stop(),
                        lambda: self.planner.stop()):
            try:
                stopper()
            except Exception:
                pass
        try:
            self._flush_traffic()
        except Exception:
            pass
        try:
            self.db.close()
        except Exception:
            pass

    # ---------- фоновые циклы ----------

    def _traffic_loop(self):
        while not self._stop_event.is_set():
            try:
                counters = psutil.net_io_counters(pernic=True)
                now = time.time()
                cur = {}
                for name, c in counters.items():
                    if name.lower().startswith(("loopback", "lo")):
                        continue
                    if c.bytes_sent == 0 and c.bytes_recv == 0:
                        continue
                    cur[name] = (c.bytes_sent, c.bytes_recv)

                pernic, total_up, total_down = {}, 0, 0
                last = self._psutil_last or {}
                for name, (s, r) in cur.items():
                    if name in last:
                        d_up = max(0, s - last[name][0])
                        d_down = max(0, r - last[name][1])
                        if d_up or d_down:
                            total_up += d_up
                            total_down += d_down
                            pernic[name] = {"up_kbps": round(d_up / 1024, 1),
                                            "down_kbps": round(d_down / 1024, 1)}
                self._psutil_last = cur

                with self._lock:
                    snap = self.snapshot
                    snap["ts"] = now
                    snap["down_kbps"] = round(total_down / 1024, 1)
                    snap["up_kbps"] = round(total_up / 1024, 1)
                    snap["total_kbps"] = round((total_down + total_up) / 1024, 1)
                    snap["total_down_mb"] += total_down / 1048576
                    snap["total_up_mb"] += total_up / 1048576
                    snap["max_kbps"] = max(snap["max_kbps"], snap["total_kbps"])
                    snap["pernic"] = pernic
                    self.history.append((now, snap["down_kbps"], snap["up_kbps"],
                                         snap["ping"].get("current")))
            except Exception as e:
                logger.info(f"[traffic] {e}")
            self._stop_event.wait(1)

    def _tick_loop(self):
        while not self._stop_event.is_set():
            try:
                pstats = self.pinger.get_stats()
                ping_ms = pstats.get("current")
                jitter = float(pstats.get("jitter") or 0)
                loss = float(pstats.get("loss") or 0)

                score = quality_score(ping_ms, jitter, loss, self.cfg.get("quality", {}))
                label, color = quality_label(score)

                cpu = psutil.cpu_percent(interval=None)
                vm = psutil.virtual_memory()

                with self._lock:
                    snap = self.snapshot
                    snap["ping"] = {
                        "current": ping_ms,
                        "jitter": round(jitter, 1),
                        "loss_pct": round(loss, 2),
                        "min": round(pstats.get("min") or 0, 1),
                        "max": round(pstats.get("max") or 0, 1),
                    }
                    snap["quality"] = {"score": score, "label": label, "color": color}
                    snap["uptime_sec"] = int(time.time() - self.started_at)
                    snap["system"] = {
                        "cpu": round(cpu, 1),
                        "mem_pct": round(vm.percent, 1),
                        "mem_used_gb": round((vm.total - vm.available) / 1073741824, 2),
                        "mem_total_gb": round(vm.total / 1073741824, 2),
                    }
                    if hasattr(self, "_ram_hist"):
                        self._ram_hist.append((self._tick, round(vm.percent, 1)))

                if self.cfg.get("ai", {}).get("enabled", True):
                    result = self.ai.process_traffic_data({
                        "speed": self.snapshot.get("total_kbps", 0),
                        "bytes_in": self.snapshot.get("down_kbps", 0) * 1024,
                        "bytes_out": self.snapshot.get("up_kbps", 0) * 1024,
                        "ping_ms": ping_ms or 0,
                        "jitter": jitter,
                        "loss": loss,
                    })
                    analysis = result.get("analysis", {})
                    if analysis.get("is_anomaly"):
                        explanation = self._explain_anomaly()
                        if explanation:
                            self.push_alert(
                                "AI_ANOMALY_EXPLAINED",
                                f"Аномалия ({analysis.get('confidence', 0):.2f}): {explanation}",
                                "ai_agent", rate=120)

                self._tick += 1
                if self._tick % 5 == 0:
                    self._flush_traffic()
                    self.quota.usage()
                if self._tick % 15 == 0:
                    try:
                        row = self.db.execute(
                            "SELECT COUNT(*) AS n FROM alerts WHERE acknowledged = 0",
                            fetch=True)
                        with self._lock:
                            self.snapshot["alerts_unread"] = (row[0]["n"] if row else 0) or 0
                    except Exception:
                        pass
                    self._build_state_cache()
            except Exception as e:
                logger.info(f"[tick] {e}")
            self._stop_event.wait(1)

    def _procmon_loop(self):
        while not self._stop_event.is_set():
            try:
                self.procmon.sample()
            except Exception as e:
                logger.info(f"[procmon] {e}")
            self._stop_event.wait(2)

    def _cleanup_loop(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(3600)
            try:
                self.db.cleanup_old_records(self.cfg.get("db_cleanup_days", 30))
            except Exception as e:
                logger.info(f"[cleanup] {e}")

    # ---------- кэш состояния для SSE ----------

    def _build_state_cache(self):
        payload = json_dumps(self.get_snapshot())
        with self._lock:
            self._cached_state_json = payload
            self._cached_state_ts = time.time()

    def state_json_cached(self):
        if time.time() - self._cached_state_ts > 1.5:
            self._build_state_cache()
        with self._lock:
            return self._cached_state_json

    # ---------- данные ----------

    def get_snapshot(self):
        with self._lock:
            import copy as _copy
            return _copy.deepcopy(self.snapshot)

    def get_history(self, seconds=300):
        cutoff = time.time() - seconds
        with self._lock:
            return [h for h in self.history if h[0] >= cutoff]

    def forecast_speed(self):
        """Линейный прогноз скорости на 5 минут вперёд (numpy polyfit)"""
        pts = self.get_history(600)
        if len(pts) < 30:
            return None
        xs = [p[0] for p in pts]
        ys = [p[1] + p[2] for p in pts]
        n = len(xs)
        x0 = xs[0]
        xs_rel = [x - x0 for x in xs]
        mean_x = sum(xs_rel) / n
        mean_y = sum(ys) / n
        num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs_rel, ys))
        den = sum((x - mean_x) ** 2 for x in xs_rel) or 1
        slope = num / den
        future_x = xs_rel[-1] + 300
        predicted = max(0.0, mean_y + slope * (future_x - mean_x))
        return {
            "predicted_kbps_5min": round(predicted, 1),
            "slope_kbps_per_min": round(slope * 60, 2),
            "based_on_points": n,
        }

    def _explain_anomaly(self):
        """Объяснение аномалии z-оценками фич относительно последних минут"""
        pts = self.get_history(600)
        if len(pts) < 30:
            return ""
        downs = [p[1] for p in pts]
        ups = [p[2] for p in pts]
        cur_down, cur_up = downs[-1], ups[-1]

        parts = []

        def zscore(series, val):
            mean = sum(series[:-1]) / max(len(series) - 1, 1)
            var = sum((x - mean) ** 2 for x in series[:-1]) / max(len(series) - 1, 1)
            std = var ** 0.5 or 1
            return (val - mean) / std

        zd, zu = zscore(downs, cur_down), zscore(ups, cur_up)
        if zd > 2.5:
            parts.append(f"всплеск загрузки ×{zd:.1f}σ ({cur_down:.0f} KB/s)")
        if zu > 2.5:
            parts.append(f"всплеск отдачи ×{zu:.1f}σ ({cur_up:.0f} KB/s)")
        return "; ".join(parts) if parts else ""

    def db_history(self, hours=24):
        fmt = "%Y-%m-%d %H:%M" if hours <= 6 else "%Y-%m-%d %H"
        rows_t = self.db.execute(
            f"""SELECT strftime('{fmt}', timestamp) AS bucket,
                       AVG(speed) AS kbps, SUM(bytes_in_delta) AS din, SUM(bytes_out_delta) AS dout
                FROM traffic
                WHERE timestamp > datetime('now','localtime', ?)
                GROUP BY bucket ORDER BY bucket""",
            (f"-{int(hours*60)} minutes",), fetch=True) or []
        rows_p = self.db.execute(
            f"""SELECT strftime('{fmt}', timestamp) AS bucket,
                       AVG(ping_ms) AS ping, AVG(jitter) AS jitter,
                       AVG(loss)*100.0 AS loss
                FROM pings
                WHERE timestamp > datetime('now','localtime', ?)
                GROUP BY bucket ORDER BY bucket""",
            (f"-{int(hours*60)} minutes",), fetch=True) or []
        pmap = {r["bucket"]: r for r in rows_p}
        merged = []
        for r in rows_t:
            p = pmap.get(r["bucket"], {})
            merged.append({
                "t": r["bucket"],
                "kbps": round(r["kbps"] or 0, 1),
                "in_mb": round((r["din"] or 0) / 1048576, 2),
                "out_mb": round((r["dout"] or 0) / 1048576, 2),
                "ping": round(p.get("ping") or 0, 1),
                "jitter": round(p.get("jitter") or 0, 1),
                "loss": round(p.get("loss") or 0, 2),
            })
        return merged

    def connections(self, limit=150, include_listening=False):
        try:
            raw = psutil.net_connections(kind="inet")
        except Exception as e:
            return {"error": str(e)}

        pid_names = {}
        for p in psutil.process_iter(["pid", "name"]):
            try:
                pid_names[p.info["pid"]] = p.info["name"] or "?"
            except Exception:
                pass

        conns, seen = [], set()
        for c in raw:
            if include_listening or c.status != "LISTEN":
                key = (c.pid, str(c.laddr), str(c.raddr), c.status)
                if key in seen:
                    continue
                seen.add(key)
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                conns.append({
                    "process": pid_names.get(c.pid, "-"),
                    "pid": c.pid or 0,
                    "local": laddr,
                    "remote": raddr,
                    "status": c.status,
                })
                if len(conns) >= limit:
                    break
        return conns

    def top_processes_by_conns(self, limit=8):
        counts = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status in ("ESTABLISHED", "SYN_SENT") and c.pid:
                    counts[c.pid] = counts.get(c.pid, 0) + 1
        except Exception:
            return []
        out = []
        for pid, n in sorted(counts.items(), key=lambda x: -x[1])[:limit]:
            name = "?"
            try:
                name = psutil.Process(pid).name()
            except Exception:
                pass
            out.append({"pid": pid, "name": name, "conns": n})
        return out

    def interfaces_info(self):
        info = []
        try:
            addrs = psutil.net_if_addrs()
        except Exception as e:
            return {"error": str(e)}
        try:
            stats = psutil.net_if_stats()
        except Exception:
            stats = {}
        with self._lock:
            live = self.snapshot.get("pernic", {})
        for name, addr_list in addrs.items():
            # Один проблемный адаптер не должен ломать весь список
            try:
                if name.lower().startswith(("loopback", "lo")):
                    continue
                ipv4 = next((a.address for a in addr_list
                             if getattr(a.family, "name", "") == "AF_INET"), None)
                mac = next((a.address for a in addr_list
                            if getattr(a.family, "name", "") in ("AF_LINK", "packet")), "")
                st = stats.get(name)
                info.append({
                    "name": name,
                    "ipv4": ipv4,
                    "mac": mac,
                    "up": bool(getattr(st, "isup", False)) if st else None,
                    "speed_mbps": getattr(st, "speed", 0) or None if st else None,
                    "down_kbps": (live.get(name, {}) or {}).get("down_kbps", 0),
                    "up_kbps": (live.get(name, {}) or {}).get("up_kbps", 0),
                })
            except Exception as e:
                logger.info(f"[ifaces] {name}: {e}")
        return info

    # ---------- алерты ----------

    def push_alert(self, alert_type, message, source, rate=0):
        now = time.time()
        rl_key = f"{source}:{alert_type}"
        if rate and now - self._alert_rl.get(rl_key, 0) < rate:
            return
        self._alert_rl[rl_key] = now
        try:
            self.db.execute(
                """INSERT INTO alerts (timestamp, alert_type, message, source)
                   VALUES (?,?,?,?)""",
                (_now_iso(), alert_type, message, source))
            with self._lock:
                self.live_alerts.appendleft({
                    "timestamp": _now_iso(), "type": alert_type,
                    "message": message, "source": source})
            self.notify_external(alert_type, message)
        except Exception as e:
            logger.info(f"[alerts] {e}")

    def notify_external(self, alert_type, message):
        tg = self.cfg.get("telegram", {})
        if tg.get("enabled") and tg.get("token") and tg.get("chat_id"):
            def send_tg():
                try:
                    url = (f"https://api.telegram.org/bot{tg['token']}/sendMessage")
                    from urllib.request import Request, urlopen
                    import urllib.parse
                    body = urllib.parse.urlencode({
                        "chat_id": tg["chat_id"],
                        "text": f"[NetPulse] {alert_type}\n{message}",
                    }).encode()
                    req = Request(url, data=body)
                    urlopen(req, timeout=5)
                except Exception:
                    pass
            threading.Thread(target=send_tg, daemon=True).start()

        # Generic webhook: Slack/Discord/Mattermost/Teams/свой бэкенд
        wh = self.cfg.get("webhook") or {}
        if wh.get("enabled") and wh.get("url"):
            def send_hook():
                try:
                    from urllib.request import Request, urlopen
                    payload = json.dumps({
                        "type": alert_type, "message": message,
                        "source": "netpulse",
                        "ts": _now_iso(),
                        "text": f"[NetPulse] {alert_type}: {message}",
                    }, ensure_ascii=False).encode("utf-8")
                    req = Request(wh["url"], data=payload,
                                  headers={"Content-Type":
                                           "application/json; charset=utf-8"})
                    urlopen(req, timeout=5)
                except Exception:
                    pass
            threading.Thread(target=send_hook, daemon=True).start()

        # Email (SMTP, stdlib)
        em = self.cfg.get("email") or {}
        if em.get("enabled") and em.get("smtp_host") and em.get("to"):
            def send_mail():
                try:
                    import smtplib
                    from email.mime.text import MIMEText
                    from email.header import Header
                    msg = MIMEText(f"{message}\n\nИсточник: {source}\n"
                                   f"Время: {_now_iso()}",
                                   "plain", "utf-8")
                    msg["Subject"] = Header(
                        f"[NetPulse] {alert_type}", "utf-8")
                    msg["From"] = em.get("from") or "netpulse@localhost"
                    msg["To"] = em["to"]
                    srv = smtplib.SMTP(em["smtp_host"],
                                       int(em.get("smtp_port") or 25),
                                       timeout=10)
                    try:
                        if em.get("use_tls"):
                            srv.starttls()
                        if em.get("user") and em.get("password"):
                            srv.login(em["user"], em["password"])
                        srv.sendmail(msg["From"], [em["to"]], msg.as_string())
                    finally:
                        srv.quit()
                except Exception as e:
                    logger.warning(f"email: {e}")
            threading.Thread(target=send_mail, daemon=True).start()

    # ---------- сохранение ----------

    def profile_thresholds(self, dtype=None):
        """Пороговые профили по группам устройств (quality.profiles)."""
        profiles = (self.cfg.get("quality") or {}).get("profiles") or {}
        key = dtype or "default"
        p = profiles.get(key) or profiles.get("default") or {}
        if not p:
            return None
        return {
            "ping_high": p.get("warn_ping_ms", 120) * 1.25,
            "jitter_high": p.get("max_jitter_ms", 15),
            "loss_high": p.get("max_loss_pct", 2),
        }

    def _alert_thresholds(self):
        q = self.cfg.get("quality", {})
        return {
            "ping_high": q.get("warn_ping_ms", 120) * 1.25,
            "jitter_high": q.get("max_jitter_ms", 15),
            "loss_high": q.get("max_loss_pct", 2),
            "loss_critical": max(5, q.get("max_loss_pct", 2) * 2.5),
        }

    def _save_pings(self, saves):
        self.db.execute_many(
            """INSERT INTO pings (timestamp, ping_ms, loss, jitter, target)
               VALUES (?,?,?,?,?)""",
            [(s["timestamp"], s["ping_ms"], s["loss"], s["jitter"], s["target"])
             for s in saves])

    def _flush_traffic(self):
        with self._lock:
            down = self.snapshot.get("down_kbps", 0)
            up = self.snapshot.get("up_kbps", 0)
            td = int(self.snapshot.get("total_down_mb", 0) * 1048576)
            tu = int(self.snapshot.get("total_up_mb", 0) * 1048576)
        if down or up:
            self.db.execute(
                """INSERT INTO traffic
                   (timestamp, speed, bytes_in, bytes_out, bytes_in_delta, bytes_out_delta)
                   VALUES (?,?,?,?,?,?)""",
                (_now_iso(), down + up, td, tu, int(down * 1024 * 5), int(up * 1024 * 5)))

    def _on_ai_alert(self, data):
        conf = float(data.get("confidence") or 0)
        self.push_alert(
            "AI_ANOMALY",
            f"Аномалия трафика (уверенность {conf:.2f}): {data.get('features', {})}",
            "ai_agent", rate=60)

    def _training_provider(self):
        traffic = self.db.execute(
            """SELECT timestamp, speed, bytes_in_delta AS bytes_in, bytes_out_delta AS bytes_out
               FROM traffic
               WHERE speed IS NOT NULL AND timestamp > datetime('now','localtime','-3 hours')
               ORDER BY timestamp DESC LIMIT 800""", fetch=True) or []
        pings = self.db.execute(
            """SELECT timestamp, ping_ms, jitter FROM pings
               WHERE ping_ms IS NOT NULL AND timestamp > datetime('now','localtime','-3 hours')
               ORDER BY timestamp DESC LIMIT 800""", fetch=True) or []
        pmap = {p["timestamp"][:19]: p for p in pings}
        out = []
        for r in traffic:
            p = pmap.get(r["timestamp"][:19], {})
            out.append({
                "speed": r["speed"],
                "bytes_in": r["bytes_in"],
                "bytes_out": r["bytes_out"],
                "ping_ms": p.get("ping_ms") or 0,
                "jitter": p.get("jitter") or 0,
            })
        return out

    def apply_settings(self, updates):
        from .config import merge_updates, save_config
        merge_updates(self.cfg, updates)
        save_config(self.cfg)
        try:
            self.pinger.set_target(self.cfg.get("ping_target", "8.8.8.8"))
            self.pinger.set_thresholds(self._alert_thresholds())
        except Exception as e:
            logger.warning(f"apply_settings: пингер не обновлён: {e}")
        try:
            self.ai.set_enabled(bool(self.cfg.get("ai", {}).get("enabled", True)))
            th = float(self.cfg.get("ai", {}).get("anomaly_threshold", 0.6))
            self.ai.traffic_agent.anomaly_threshold = th
        except Exception as e:
            logger.warning(f"apply_settings: AI не обновлён: {e}")
        return True

    # ---------- новый функционал: SLA, гео, RAM-прогноз, MTR-веер ----------

    def mtr_history(self, hours=24):
        hours = min(max(int(hours), 1), 168)
        try:
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS mtr_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL, target TEXT NOT NULL,
                    hop INTEGER, ip TEXT, loss_pct REAL, avg_ms REAL)""")
        except Exception as e:
            logger.debug("mtr_history table: %s", e)
        return self.db.execute(
            """SELECT ts, target, hop, ip, loss_pct, avg_ms FROM mtr_history
               WHERE ts > datetime('now','localtime', ? || ' hours')
               ORDER BY id ASC""", (f"-{hours}",), fetch=True) or []

    def sla_period(self, days=30):
        """SLA-доступность узлов за период по hosts + WATCH_OFFLINE событиям."""
        days = min(max(int(days), 1), 90)
        since = f"-{days} days"
        hosts = self.db.execute(
            """SELECT h.id, h.name, h.ip, h.online, h.first_seen, h.last_seen
               FROM hosts h""", fetch=True) or []
        out = []
        for h in hosts:
            offs = self.db.execute(
                """SELECT COUNT(*) AS n FROM events
                   WHERE host_id = ? AND kind IN ('OFFLINE','WATCH_OFFLINE')
                     AND timestamp > datetime('now','localtime', ?)""",
                (h["id"], since), fetch=True) or [{}]
            ons = self.db.execute(
                """SELECT COUNT(*) AS n FROM events
                   WHERE host_id = ? AND kind = 'ONLINE'
                     AND timestamp > datetime('now','localtime', ?)""",
                (h["id"], since), fetch=True) or [{}]
            n_off = (offs[0]["n"] if offs else 0) or 0
            n_on = (ons[0]["n"] if ons else 0) or 0
            # грубая оценка: downtime = события OFFLINE без подтверждения ONLINE
            est = 100.0 - min(100.0, n_off * 5 if n_off else 0)
            out.append({
                "id": h["id"], "name": h["name"], "ip": h["ip"],
                "online": bool(h["online"]),
                "offline_events": n_off, "online_events": n_on,
                "sla_pct": round(max(0.0, est), 2),
                "first_seen": h["first_seen"], "last_seen": h["last_seen"],
            })
        return sorted(out, key=lambda x: x["sla_pct"])

    def geo_attack_map(self, limit=150):
        """Гео-карта атак: агрегация источников из IDS/security-алертов."""
        ips = []
        for ev in list(getattr(self.procmon, "ids_events", []))[:limit]:
            msg = str(ev.get("message", ""))
            for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", msg):
                ips.append(m.group(1))
        for ev in list(getattr(self.procmon, "security_events", []))[:limit]:
            msg = str(ev.get("message", ""))
            for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", msg):
                ips.append(m.group(1))
        # отдельно публичные IP из алертов за период
        rows = self.db.execute(
            """SELECT message FROM alerts
               WHERE alert_type IN ('SUSPICIOUS_CONN','PORT_SCAN','SECURITY_SCAN')
               ORDER BY id DESC LIMIT 300""", fetch=True) or []
        for r in rows:
            for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", r["message"]):
                ips.append(m.group(1))
        return {"countries": top_countries(ips),
                "total_ips": len(ips), "uniq": len(set(ips))}

    def ram_forecast(self, days_left_cap=30):
        """Прогноз заполнения ОЗУ мастера по истории mem_pct из snapshot'ов."""
        history = self._ram_history()
        if len(history) < 3:
            return {"ok": False, "note": "мало данных (нужно 3+ точек)"}
        pts = list(history)
        slope = (pts[-1][1] - pts[0][1]) / max(len(pts) - 1, 1)
        if slope <= 0:
            return {"ok": True, "slope_pct_pt": round(slope, 3),
                    "days_left": None, "note": "ОЗУ не растёт"}
        days_left = (100.0 - pts[-1][1]) / slope
        return {"ok": True, "last_pct": pts[-1][1], "slope_pct_pt": round(slope, 3),
                "days_left": int(days_left) if days_left < days_left_cap else None}

    def _ram_history(self):
        # из кольцевого буфера mem_pct (пишется раз в секунду в _tick_loop)
        return list(getattr(self, "_ram_hist", None) or [])[-120:]

    def _l2_auto_loop(self):
        while not self._stop_event.is_set():
            try:
                self.l2map.scan()
            except Exception as e:
                logger.info(f"[l2] {e}")
            self._stop_event.wait(1800)

    def _escalate_loop(self):
        esc = self.cfg.get("escalate", {})
        timeout_min = int(esc.get("unack_min", 30) or 30)
        notified = set()
        while not self._stop_event.is_set():
            try:
                rows = self.db.execute(
                    """SELECT id, alert_type, message, source, timestamp FROM alerts
                       WHERE acknowledged = 0
                         AND timestamp <= datetime('now','localtime', ? || ' minutes')""",
                    (f"-{timeout_min}",), fetch=True) or []
                for r in rows:
                    if r["id"] in notified:
                        continue
                    notified.add(r["id"])
                    self.notify_external(
                        f"ЭСКАЛАЦИЯ: {r['alert_type']}",
                        f"{r['message']} (с {r['timestamp']})")
            except Exception as e:
                logger.info(f"[escalate] {e}")
            self._stop_event.wait(600)

    def _weekly_report_loop(self):
        while not self._stop_event.is_set():
            # авто-отчёт раз в неделю по расписанию
            try:
                from datetime import timedelta
                now = datetime.now()
                wr = self.cfg.get("report", {}).get("weekly", {}) or {}
                day = (str(wr.get("day", "mon")).lower()[:3])
                clock = str(wr.get("time", "08:00")).strip()
                if now.strftime("%a").lower().startswith(day) and \
                        now.strftime("%H:%M") == clock:
                    text = self._weekly_report_text()
                    em = self.cfg.get("email", {}) or {}
                    to = wr.get("to_email") or em.get("to") or ""
                    if em.get("enabled") and to:
                        self._send_report_email(to, text)
                    wh = self.cfg.get("webhook", {}) or {}
                    if wh.get("enabled") and wh.get("url"):
                        self._send_report_webhook(wh.get("url"), text)
                    self._stop_event.wait(86400)
            except Exception as e:
                logger.info(f"[weekly] {e}")
            self._stop_event.wait(60)

    def _weekly_report_text(self):
        lines = ["NETPULSE — еженедельный отчёт", datetime.now().isoformat(), ""]
        hosts = self.db.execute(
            "SELECT name, ip, online, health_score FROM hosts", fetch=True) or []
        lines.append(f"Машин: {len(hosts)}, онлайн: "
                     f"{sum(1 for h in hosts if h['online'])}")
        lines.append("")
        if hosts:
            lines.append("По карме (худшие):")
            for h in sorted(hosts, key=lambda x: x["health_score"] or 100)[:5]:
                lines.append(
                    f"  {h['name']} [{h['ip']}] карма {h['health_score']} "
                    f"{'онлайн' if h['online'] else 'ОФФЛАЙН'}")
        lines.append("")
        alerts = self.db.execute(
            "SELECT alert_type, COUNT(*) AS n FROM alerts "
            "WHERE timestamp > datetime('now','localtime','-7 days') "
            "GROUP BY alert_type ORDER BY n DESC LIMIT 10", fetch=True) or []
        if alerts:
            lines.append("Алерты за неделю:")
            for a in alerts:
                lines.append(f"  {a['alert_type']}: {a['n']}")
        return "\n".join(lines)

    def _send_report_email(self, to, text):
        import smtplib
        from email.mime.text import MIMEText
        em = self.cfg.get("email", {})
        try:
            msg = MIMEText(text, "plain", "utf-8")
            msg["Subject"] = "NetPulse — еженедельный отчёт"
            msg["From"] = em.get("from") or "netpulse@localhost"
            msg["To"] = to
            srv = smtplib.SMTP(em["smtp_host"], int(em.get("smtp_port") or 25),
                               timeout=10)
            try:
                if em.get("use_tls"):
                    srv.starttls()
                if em.get("user") and em.get("password"):
                    srv.login(em["user"], em["password"])
                srv.sendmail(msg["From"], [to], msg.as_string())
            finally:
                srv.quit()
        except Exception as e:
            logger.warning(f"week-report email: {e}")

    def _send_report_webhook(self, url, text):
        def send():
            try:
                from urllib.request import Request, urlopen
                req = Request(url, data=json.dumps(
                    {"type": "WEEKLY_REPORT", "text": text},
                    ensure_ascii=False).encode("utf-8"),
                    headers={"Content-Type": "application/json; charset=utf-8"})
                urlopen(req, timeout=6)
            except Exception:
                pass
        threading.Thread(target=send, daemon=True).start()

    def weekly_report_text_ep(self):
        return {"report": self._weekly_report_text()}


def json_dumps(obj):
    import json
    return json.dumps(obj, ensure_ascii=False)
