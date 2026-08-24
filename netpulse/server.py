"""
HTTP-сервер NetPulse v2 (stdlib).
REST + SSE-стрим живого состояния + Prometheus /metrics + auth-token
+ фоновые задачи (сканы, MTR, LAN) + управление Windows Firewall + автобэкапы.
"""

import hmac
import json
import time
import uuid
import re
import threading
import subprocess
import os
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timedelta
from urllib.request import urlopen, Request
from urllib.parse import urlparse, parse_qs, unquote

import psutil

from core import Tracer, SecurityScanner
from core.utils import decode_process_output

from . import __version__
from .services import MonitorService

WORKERS = ThreadPoolExecutor(max_workers=6, thread_name_prefix="np-worker")
JOBS = {}

MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}

SAFE_TARGET = re.compile(r"^[A-Za-z0-9._\-]{1,253}$")
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

# Ключи конфига, которые нельзя менять через API (только правкой config.json)
PROTECTED_SETTINGS = {"web_auth_enabled"}


def platform_report_text(svc, days=30):
    """Текстовый отчёт отдела для начальства (журнал + парк + бэкапы)."""
    rep = svc.journal.month_report(days)
    lines = [
        "=" * 56,
        f"ОТЧЁТ ОТДЕЛА ИТ  ({datetime.now():%Y-%m-%d %H:%M}, период {days} дн)",
        "=" * 56,
        "",
        f"Записей в журнале : {rep['entries']}",
        f"Затрачено времени : {rep['minutes']} мин (~{rep['hours']} ч)",
        "",
        "По источникам:",
    ]
    for s in rep["by_source"]:
        lines.append(f"  {s['source']:<10} {s['n']:>4} шт   {s['minutes']:>5} мин")
    if rep["top_users"]:
        lines += ["", "Больше всего времени:"]
        for u in rep["top_users"]:
            lines.append(f"  {u['who']:<20} {u['n']:>3} шт {u['minutes']:>5} мин")
    if rep["top_hosts"]:
        lines += ["", "Топ машин по обращениям:"]
        for h in rep["top_hosts"]:
            lines.append(f"  {h['host']:<20} {h['n']:>3} шт {h['minutes']:>5} мин")

    worst = svc.inventory.worst_hosts(5) if hasattr(svc, "inventory") else []
    if worst:
        lines += ["", "Карма парка (худшие):"]
        for w in worst:
            lines.append(f"  {w['name']:<20} карма {w['health_score']}, "
                         f"{'в сети' if w['online'] else 'НЕ В СЕТИ'}")

    try:
        evs = svc.db.execute(
            """SELECT timestamp, severity, COALESCE(h.name,''), text
               FROM events e LEFT JOIN hosts h ON h.id = e.host_id
               WHERE severity IN ('CRITICAL','HIGH')
                 AND timestamp > datetime('now','localtime', ? || ' days')
               ORDER BY e.id DESC LIMIT 15""", (f"-{days}",), fetch=True) or []
        if evs:
            lines += ["", f"Критичные события за {days} дн:"]
            for e in evs:
                lines.append(f"  [{e['timestamp'][:16]}] "
                             f"{e['severity']:<8} {e[2]}: {e['text'][:70]}")
    except Exception:
        pass

    try:
        planner = svc.planner.status_list()
        due = [p for p in planner if p["due"]]
        if due:
            lines += ["", "Просроченные плановые работы:"]
            for p in due:
                lines.append(f"  {p['name']} (каждые {p['every_days']} дн)")
    except Exception:
        pass

    lines += ["", "Сформировано NetPulse", ""]
    return "\n".join(lines)


def submit_job(fn):
    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {"status": "running", "result": None, "error": None,
                    "started": time.time()}

    def wrap():
        try:
            JOBS[job_id]["result"] = fn()
            JOBS[job_id]["status"] = "done"
        except Exception as e:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"] = str(e)

    WORKERS.submit(wrap)
    return job_id


def prune_jobs(max_age=1800):
    cutoff = time.time() - max_age
    for jid in list(JOBS.keys()):
        j = JOBS[jid]
        if j["status"] != "running" and j["started"] < cutoff:
            del JOBS[jid]


# ================= Firewall (NetLimiter/Portmaster идея) =================

class FirewallCtl:
    RULE_PREFIX = "NetPulse_"

    @staticmethod
    def admin_ok():
        """Проверка прав администратора (нужны для изменения правил firewall)"""
        if sys.platform != "win32":
            return False
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @staticmethod
    def _run(args):
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        r = subprocess.run(["netsh", "advfirewall", "firewall"] + args,
                           capture_output=True, timeout=10, creationflags=flags)
        out = decode_process_output(r.stdout + r.stderr)
        ok = r.returncode == 0 and ("Ok." in out or "ОК" in out or "обновлено" in out.lower()
                                    or "Updated" in out or "added" in out.lower()
                                    or "удалено" in out.lower() or "deleted" in out.lower())
        return ok, out.strip()[:200]

    @classmethod
    def block_ip(cls, ip, direction="both"):
        name = f"{cls.RULE_PREFIX}IP_{ip.replace(':', '_')}"
        results = []
        dirs = ["in", "out"] if direction == "both" else [direction]
        for d in dirs:
            ok, msg = cls._run(["add", "rule", f"name={name}_{d}",
                                f"dir={d}", "action=block", f"remoteip={ip}"])
            results.append({"dir": d, "ok": ok})
        return {"ok": all(x["ok"] for x in results), "results": results}

    @classmethod
    def block_app(cls, path):
        if not os.path.exists(path):
            return {"ok": False, "error": "файл не найден"}
        name = f"{cls.RULE_PREFIX}APP_{uuid.uuid4().hex[:6]}"
        results = []
        for d in ("in", "out"):
            ok, _ = cls._run(["add", "rule", f"name={name}_{d}",
                              f"dir={d}", "action=block",
                              f"program={path}", "enable=yes"])
            results.append(ok)
        return {"ok": all(results), "name": name}

    @classmethod
    def unblock(cls, rule_name):
        ok, msg = cls._run(["delete", "rule", f"name={rule_name}"])
        return {"ok": ok}

    @classmethod
    def list_rules(cls):
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        try:
            r = subprocess.run(["netsh", "advfirewall", "firewall", "show",
                                "rule", "name=all", "dir=out"],
                               capture_output=True, timeout=15, creationflags=flags)
            text = decode_process_output(r.stdout)
            rules = []
            current = {}
            for line in text.splitlines():
                line = line.strip()
                m = re.match(r"^Имя правила:\s+(.+)$|^Rule Name:\s+(.+)$", line)
                if m:
                    name = m.group(1) or m.group(2)
                    if current.get("name", "").startswith(cls.RULE_PREFIX):
                        rules.append(current)
                    current = {"name": name}
                elif current is not None:
                    m2 = re.match(r"^(?:Включено|Enabled):\s+(\S+)", line)
                    if m2:
                        current["enabled"] = m2.group(1)
                    m3 = re.match(r"^(?:Удаленный IP-адрес|RemoteIP):\s+(\S+)", line)
                    if m3:
                        current["remoteip"] = m3.group(1)
                    m4 = re.match(r"^(?:Программа|Program):\s+(.+)$", line)
                    if m4:
                        current["program"] = m4.group(1).strip()
            if current.get("name", "").startswith(cls.RULE_PREFIX):
                rules.append(current)
            return {"rules": rules}
        except Exception as e:
            return {"rules": [], "error": str(e)}


# ================= Автобэкап =================

class BackupManager:
    RAR_PATHS = ("C:\\Program Files\\WinRAR\\Rar.exe",
                 "C:\\Program Files (x86)\\WinRAR\\Rar.exe")
    EXCLUDE_DIRS = {"__pycache__", ".git"}
    EXCLUDE_SUFFIXES = (".db-wal", ".db-shm")

    def __init__(self, config):
        self.cfg = config
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._loop, daemon=True, name="np-backup").start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            self.run_backup_if_due()
            self._stop.wait(600)

    @classmethod
    def _find_rar(cls):
        for p in cls.RAR_PATHS:
            if os.path.exists(p):
                return p
        return None

    def run_backup_if_due(self):
        bc = self.cfg.get("backup", {})
        if not (bc.get("enabled") and bc.get("time")):
            return
        now = datetime.now().strftime("%H:%M")
        stamp_file = os.path.join(bc.get("dir", "C:\\Backups"), ".last_auto_run")
        target_time = bc["time"]
        today_stamp = datetime.now().strftime("%Y%m%d")
        try:
            if now >= target_time and (not os.path.exists(stamp_file)
                                       or open(stamp_file).read().strip() != today_stamp):
                self.run_backup_now()
                os.makedirs(os.path.dirname(stamp_file), exist_ok=True)
                with open(stamp_file, "w") as f:
                    f.write(today_stamp)
                self.rotate(int(bc.get("keep", 7)))
        except Exception as e:
            print(f"[backup] {e}")

    def run_backup_now(self, rar=None):
        """Бэкап исходников: WinRAR, если установлен, иначе zip из stdlib."""
        bc = self.cfg.get("backup", {})
        dest_dir = bc.get("dir", "C:\\Backups")
        os.makedirs(dest_dir, exist_ok=True)
        src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        stamp = f"{datetime.now():%Y%m%d_%H%M}"

        rar = rar if rar is not None else self._find_rar()
        if rar:
            dest = os.path.join(dest_dir, f"netpulse_auto_{stamp}.rar")
            cmd = [rar, "a", "-r", "-ep1", "-y", "-m5",
                   "-x*.db-wal", "-x*.db-shm",
                   "-x*\\__pycache__\\*", "-x*\\__pycache__",
                   dest, src]
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=300,
                                   creationflags=flags)
                if r.returncode == 0:
                    return {"ok": True, "archive": dest}
                print(f"[backup] rar завершился с кодом {r.returncode}, fallback на zip")
            except Exception as e:
                print(f"[backup] rar недоступен ({e}), fallback на zip")

        dest = os.path.join(dest_dir, f"netpulse_auto_{stamp}.zip")
        try:
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
                for root, dirs, files in os.walk(src):
                    dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]
                    for f in files:
                        if f.endswith(self.EXCLUDE_SUFFIXES):
                            continue
                        full = os.path.join(root, f)
                        if full == dest:
                            continue
                        z.write(full, os.path.relpath(full, src))
            return {"ok": True, "archive": dest}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def rotate(self, keep=7):
        dest_dir = self.cfg.get("backup", {}).get("dir", "C:\\Backups")
        try:
            archives = sorted(
                (f for f in os.listdir(dest_dir) if f.startswith("netpulse_auto_")),
                reverse=True)
            for old in archives[keep:]:
                os.remove(os.path.join(dest_dir, old))
        except Exception:
            pass


# ================= API =================

class Api:
    def __init__(self, service: MonitorService, config, backup: BackupManager):
        self.svc = service
        self.cfg = config
        self.backup = backup
        self.tracer = Tracer()

    # ----- состояние -----

    def state(self, q):
        snap = self.svc.get_snapshot()
        snap["forecast"] = self.svc.forecast_speed()
        snap["quota"] = self.svc.quota.usage()
        return snap

    def stream(self, q, handler):
        """SSE: живой поток состояния раз в секунду"""
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream; charset=utf-8")
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Connection", "keep-alive")
        handler.end_headers()

        idle_deadline = time.time() + 3600
        try:
            while not handler.close_connection and time.time() < idle_deadline:
                data = self.svc.state_json_cached()
                chunk = f"data: {data}\n\n".encode("utf-8")
                handler.wfile.write(b"data: ping\n\n")
                handler.wfile.write(chunk)
                handler.wfile.flush()
                time.sleep(1)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def history(self, q):
        minutes = int(q.get("minutes", ["30"])[0])
        seconds = min(max(minutes * 60, 60), 1800)
        rows = self.svc.get_history(seconds)
        return {"points": [
            {"t": t, "down_kbps": round(d, 1), "up_kbps": round(u, 1), "ping_ms": p}
            for t, d, u, p in rows]}

    def db_history(self, q):
        hours = min(max(int(q.get("hours", ["24"])[0]), 1), 168)
        return {"hours": hours, "buckets": self.svc.db_history(hours)}

    def interfaces(self, q):
        return self.svc.interfaces_info()

    def connections(self, q):
        include_listen = q.get("listening", ["0"])[0] == "1"
        limit = min(int(q.get("limit", ["150"])[0]), 500)
        conns = self.svc.connections(limit=limit + 50,
                                     include_listening=include_listen)
        if isinstance(conns, dict):
            return conns
        est = [c for c in conns if c["status"] != "LISTEN"]
        data = (conns if include_listen else est)[:limit]
        return {"count": len(data), "connections": data}

    def top_processes(self, q):
        return {"processes": self.svc.top_processes_by_conns()}

    # ----- приложения (GlassWire/NetLimiter идея) -----

    def apps(self, q):
        procs = self.svc.procmon.top_io(40)
        return {"apps": procs, "admin": self.svc.snapshot["mode"]["admin"]}

    def app_new_connections(self, q):
        return {"events": self.svc.procmon.new_connections(80)}

    def firewall_block_ip(self, q):
        body = self._read_body()
        ip = str(body.get("ip", "")).strip()
        if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
            return (400, {"error": "нужен IPv4"})
        res = FirewallCtl.block_ip(ip)
        if res.get("ok"):
            self.svc.push_alert("FIREWALL_BLOCK", f"IP {ip} заблокирован в Windows Firewall",
                                "firewall")
        return res

    def app_exe(self, q):
        """Путь к исполняемому файлу процесса (для блокировки приложения)"""
        try:
            pid = int(q.get("pid", ["0"])[0])
            exe = psutil.Process(pid).exe()
            return {"pid": pid, "exe": exe or ""}
        except Exception:
            return {"pid": 0, "exe": "", "error": "процесс недоступен"}

    def firewall_block_app(self, q):
        body = self._read_body()
        pid = int(body.get("pid") or 0)
        path = str(body.get("path", "")).strip()
        if not path and pid:
            try:
                path = psutil.Process(pid).exe() or ""
            except Exception:
                path = ""
        if not path or not os.path.exists(path):
            return (400, {"error": "путь к exe не найден (запустите от админа или укажите вручную)"})
        res = FirewallCtl.block_app(path)
        if res.get("ok"):
            self.svc.push_alert("FIREWALL_BLOCK_APP",
                                f"Приложение заблокировано: {path}", "firewall")
        res["path"] = path
        return res

    def firewall_rules(self, q):
        return FirewallCtl.list_rules()

    def firewall_unblock(self, q):
        body = self._read_body()
        name = str(body.get("name", ""))
        if not name.startswith(FirewallCtl.RULE_PREFIX):
            return (400, {"error": "можно удалять только правила NetPulse"})
        return FirewallCtl.unblock(name)

    # ----- IDS -----

    def ids_feed(self, q):
        return {"events": self.svc.procmon.ids_feed(80)}

    # ----- диагностика -----

    def ping_probe(self, q):
        target = (q.get("target", [""])[0] or "").strip()
        if not SAFE_TARGET.match(target):
            return (400, {"error": "некорректный адрес"})
        count = min(int(q.get("count", ["5"])[0]), 10)
        from core.utils import parse_ping_output
        import subprocess as sp
        results = []
        for i in range(count):
            cmd = (["ping", "-n", "1", "-w", "2000", target] if sys.platform == "win32"
                   else ["ping", "-c", "1", "-W", "2", target])
            try:
                proc = sp.run(cmd, capture_output=True, timeout=4,
                              creationflags=subprocess.CREATE_NO_WINDOW
                              if sys.platform == "win32" else 0)
                out = decode_process_output(proc.stdout + proc.stderr)
                ms, loss = parse_ping_output(out)
                results.append({"ok": not loss, "ms": ms})
            except Exception:
                results.append({"ok": False, "ms": None})
        oks = [r["ms"] for r in results if r["ok"]]
        return {
            "target": target, "results": results,
            "avg_ms": round(sum(oks) / len(oks), 1) if oks else None,
            "loss_pct": round(100 * (count - len(oks)) / count, 1),
        }

    def trace(self, q):
        target = (q.get("target", [""])[0] or "").strip()
        max_hops = min(int(q.get("max", ["14"])[0]), 20)
        if not SAFE_TARGET.match(target):
            return (400, {"error": "некорректный адрес"})
        result = self.tracer.trace(target, max_hops=max_hops)
        self.svc.db.execute(
            """INSERT INTO traces (timestamp, target, hops, avg_ms)
               VALUES (?,?,?,?)""",
            (datetime.now().isoformat(), target, result.get("total_hops", 0),
             result.get("avg_ms", 999)))
        return result

    def trace_targets(self, q):
        targets = self.cfg.get("diagnostics", {}).get("trace_targets", [])
        jobs = {t: submit_job(lambda tt=t: self.tracer.trace(tt)) for t in targets}
        results = {}
        for t, jid in jobs.items():
            deadline = time.time() + 120
            while time.time() < deadline:
                j = JOBS.get(jid, {})
                if j.get("status") != "running":
                    results[t] = j.get("result") if j.get("status") == "done" \
                        else {"error": j.get("error")}
                    break
                time.sleep(1)
            else:
                results[t] = {"error": "timeout"}
        return results

    def dns_best(self, q):
        return self.tracer.find_best_dns()

    def dns_resolve(self, q):
        import socket
        hosts = set(q.get("hosts", self.cfg.get("diagnostics", {})
                          .get("resolve_hosts", [])))
        out = []
        for host in sorted(str(h) for h in hosts)[:12]:
            try:
                t0 = time.perf_counter()
                infos = socket.getaddrinfo(host, 443, socket.AF_INET)
                ms = (time.perf_counter() - t0) * 1000
                ip = infos[0][4][0] if infos else "?"
                out.append({"host": host, "ip": ip, "ms": round(ms, 1)})
            except Exception:
                out.append({"host": host, "ip": None, "ms": None})
        return {"results": out}

    def speedtest(self, q):
        st = self.cfg.get("speedtest", {})
        nbytes = min(int(q.get("bytes", [st.get("bytes", 8000000)])[0]), 64_000_000)
        timeout = int(st.get("timeout_sec", 20))
        t0 = time.perf_counter()
        received = 0
        url = st.get("url_down", "").format(bytes=nbytes)
        req = Request(url, headers={"User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetPulse/" + __version__})
        with urlopen(req, timeout=timeout) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                received += len(chunk)
                if time.perf_counter() - t0 > timeout:
                    break
        elapsed = max(time.perf_counter() - t0, 1e-6)
        mbps = received * 8 / elapsed / 1e6
        self.svc.db.execute(
            """INSERT INTO speedtest_log (timestamp, mbps, direction, bytes)
               VALUES (?,?,?,?)""",
            (datetime.now().isoformat(), round(mbps, 2), "down", received))
        return {"bytes": received, "seconds": round(elapsed, 2), "mbps": round(mbps, 2)}

    def speedtest_upload(self, q):
        st = self.cfg.get("speedtest", {})
        nbytes = min(int(q.get("bytes", [2000000])[0]), 16_000_000)
        url = st.get("url_up", "")
        payload = b"x" * 65536
        t0 = time.perf_counter()
        sent = 0
        try:
            while sent < nbytes and time.perf_counter() - t0 < st.get("timeout_sec", 20):
                req = Request(url, data=payload, method="POST",
                              headers={"User-Agent":
                                  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetPulse/"
                                  + __version__})
                urlopen(req, timeout=10).read(64)
                sent += len(payload)
        except Exception:
            pass
        elapsed = max(time.perf_counter() - t0, 1e-6)
        mbps = sent * 8 / elapsed / 1e6
        self.svc.db.execute(
            """INSERT INTO speedtest_log (timestamp, mbps, direction, bytes)
               VALUES (?,?,?,?)""",
            (datetime.now().isoformat(), round(mbps, 2), "up", sent))
        return {"bytes": sent, "seconds": round(elapsed, 2),
                "mbps": round(mbps, 2), "note": "оценочно при успешных ответах"}

    def speedtest_log(self, q):
        rows = self.svc.db.execute(
            """SELECT timestamp, mbps, direction FROM speedtest_log
               ORDER BY id DESC LIMIT 30""", fetch=True) or []
        return {"log": rows}

    # ----- MTR -----

    def mtr_start(self, q):
        body = self._read_body()
        self.svc.mtr.start(target=body.get("target"),
                           max_hops=body.get("max_hops"),
                           cycle_sec=body.get("cycle_sec"))
        return {"ok": True}

    def mtr_stop(self, q):
        self.svc.mtr.stop()
        return {"ok": True}

    def mtr_stats(self, q):
        return self.svc.mtr.stats()

    # ----- LAN -----

    def lan_scan(self, q):
        job_id = submit_job(lambda: self.svc.lan.scan())
        deadline = time.time() + 90
        while time.time() < deadline:
            j = JOBS.get(job_id, {})
            if j.get("status") != "running":
                return {"devices": j.get("result") or [],
                        "error": j.get("error")} if j.get("status") == "done" \
                    else {"error": j.get("error")}
            time.sleep(1.5)
        return (504, {"error": "скан превысил таймаут"})

    def lan_devices(self, q):
        return {"devices": self.svc.lan.devices_from_db()}

    def lan_alias(self, q):
        body = self._read_body()
        mac = str(body.get("mac") or "").strip()
        alias = str(body.get("alias") or "").strip()[:80]
        if not re.match(r"^[0-9A-Fa-f:\.\-]{12,17}$", mac):
            return (400, {"error": "некорректный MAC"})
        n = self.svc.db.execute(
            "UPDATE lan_devices SET alias = ? WHERE mac = ?", (alias, mac))
        return {"ok": bool(n), "mac": mac, "alias": alias}

    def port_scan(self, q):
        body = self._read_body()
        host = str(body.get("host", "")).strip()
        ports = body.get("ports")
        if not SAFE_TARGET.match(host):
            return (400, {"error": "некорректный хост"})
        if isinstance(ports, list) and ports:
            try:
                ports = [int(p) for p in ports][:100]
            except Exception:
                ports = None
        from .services import PortScanner
        job_id = submit_job(lambda: PortScanner.tcp_scan(host, ports))
        deadline = time.time() + 60
        while time.time() < deadline:
            j = JOBS.get(job_id, {})
            if j.get("status") != "running":
                return j.get("result") if j.get("status") == "done" \
                    else {"error": j.get("error")}
            time.sleep(1)
        return (504, {"error": "таймаут сканирования"})

    # ----- безопасность -----
    def security_scan(self, q):
        body = self._read_body()
        quick = bool(body.get("quick"))
        ports = self.cfg.get("security", {}).get("suspicious_ports", [])
        if quick:
            fn = lambda: {
                "Подозрительные соединения":
                    SecurityScanner.detect_suspicious_connections(ports),
                "HOSTS файл": SecurityScanner.check_hosts_file(),
            }
        else:
            fn = lambda: SecurityScanner.run_full_scan(ports)

        job_id = submit_job(fn)

        def finalize():
            deadline = time.time() + 300
            while time.time() < deadline:
                j = JOBS.get(job_id, {})
                if j.get("status") != "running":
                    res = j.get("result") or {}
                    total = sum(len(v) for v in res.values()) if isinstance(res, dict) else 0
                    self.svc.push_alert(
                        "SECURITY_SCAN",
                        f"Скан завершён: угроз {total} ({'быстрый' if quick else 'полный'})",
                        "scanner")
                    return
                time.sleep(1)

        WORKERS.submit(finalize)
        return {"job": job_id}

    def security_result(self, q):
        job_id = q.get("job", [""])[0]
        j = JOBS.get(job_id)
        if not j:
            return (404, {"error": "задача не найдена"})
        return {"status": j["status"], "result": j["result"], "error": j["error"]}

    # ----- захват пакетов -----

    def capture_start(self, q):
        body = self._read_body()
        return self.svc.capture.start(filter_proto=body.get("proto"))

    def capture_stop(self, q):
        self.svc.capture.stop()
        return {"ok": True}

    def capture_state(self, q):
        return self.svc.capture.snapshot(120)

    # ----- алерты -----

    def alerts(self, q):
        limit = min(int(q.get("limit", ["80"])[0]), 300)
        rows = self.svc.db.execute(
            """SELECT id, timestamp, alert_type, message, source, acknowledged
               FROM alerts ORDER BY id DESC LIMIT ?""",
            (limit,), fetch=True) or []
        unread = self.svc.db.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE acknowledged = 0", fetch=True)
        return {"alerts": rows,
                "unread": (unread[0]["n"] if unread else 0) or 0,
                "live": list(self.svc.live_alerts)[:20]}

    def alerts_ack(self, q):
        body = self._read_body()
        alert_id = body.get("id")
        if alert_id:
            self.svc.db.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
        else:
            self.svc.db.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
        return {"ok": True}

    # ----- AI -----

    def ai_stats(self, q):
        stats = self.svc.ai.get_stats()
        pred = self.svc.ai.predictive_agent.predict_next("speed")
        anomalies = self.svc.ai.get_anomalies(15)
        cfg_ai = self.cfg.get("ai", {})
        return {
            "enabled": cfg_ai.get("enabled", True),
            "threshold": cfg_ai.get("anomaly_threshold", 0.6),
            "stats": stats.get("traffic", {}),
            "forecast": self.svc.forecast_speed(),
            "prediction": {k: v for k, v in pred.items() if k != "timestamp"}
            if "error" not in pred else None,
            "anomalies": list(reversed(anomalies)),
        }

    def ai_train(self, q):
        data = self.svc._training_provider()
        ok = self.svc.ai.train_model(data) if data and len(data) >= 10 else False
        return {"ok": ok, "samples": len(data or [])}

    # ----- настройки / бэкапы -----

    def settings_get(self, q):
        cfg = json.loads(json.dumps(self.cfg))
        token = cfg.get("web_token", "")
        if token:
            cfg["web_token_masked"] = token[:6] + "..." + token[-4:]
        return cfg

    def settings_post(self, q):
        body = self._read_body()
        regen = body.pop("_regen_token", False)
        for key in PROTECTED_SETTINGS:
            body.pop(key, None)
        if regen:
            body.setdefault("web_token", uuid.uuid4().hex)
        self.svc.apply_settings(body)
        return {"ok": True, "config": self.cfg}

    def backup_run(self, q):
        res = self.backup.run_backup_now()
        if res.get("ok"):
            self.backup.rotate(int(self.cfg.get("backup", {}).get("keep", 7)))
        return res

    def backup_list(self, q):
        d = self.cfg.get("backup", {}).get("dir", "C:\\Backups")
        try:
            files = sorted((f for f in os.listdir(d)
                            if f.endswith((".rar", ".zip"))), reverse=True)[:20]
            out = [{"name": f,
                    "size_mb": round(os.path.getsize(os.path.join(d, f)) / 1048576, 1)}
                   for f in files]
            return {"backups": out, "dir": d}
        except Exception as e:
            return {"backups": [], "error": str(e)}

    # ----- отчёты -----

    def report_data(self, q):
        snap = self.svc.get_snapshot()
        agg = self.svc.db.execute(
            """SELECT COUNT(*) AS samples, AVG(speed) AS avg_kbps, MAX(speed) AS max_kbps
               FROM traffic WHERE timestamp > datetime('now','localtime','-24 hours')""",
            fetch=True)
        ping = self.svc.db.execute(
            """SELECT AVG(ping_ms) AS avg_ping, AVG(loss)*100 AS loss
               FROM pings WHERE timestamp > datetime('now','localtime','-24 hours')""",
            fetch=True)
        return {
            "generated": datetime.now().isoformat(),
            "app": f"NetPulse v{__version__}",
            "live": snap,
            "quota": self.svc.quota.usage(),
            "day_stats": (agg[0] if agg else {}),
            "ping_stats": (ping[0] if ping else {}),
            "recent_alerts": list(self.svc.live_alerts),
        }

    # ----- платформа отдела: журнал / парк / кнопки -----

    def journal_list(self, q):
        limit = min(int(q.get("limit", ["150"])[0] or 150), 500)
        source = q.get("source", [None])[0]
        text = q.get("q", [None])[0]
        return {"entries": self.svc.journal.list_entries(limit, source, text)}

    def journal_add(self, q):
        body = self._read_body()
        return self.svc.journal.add(
            text=body.get("text"),
            source=str(body.get("source") or "manual"),
            host=body.get("host"),
            user_name=body.get("user"),
            minutes=body.get("minutes") or 0)

    def journal_delete(self, q):
        body = self._read_body()
        return self.svc.journal.delete(body.get("id"))

    def journal_report(self, q):
        days = q.get("days", ["30"])[0]
        rep = self.svc.journal.month_report(days)
        worst = self.svc.inventory.worst_hosts(3) if hasattr(
            self.svc, "inventory") else []
        rep["worst_hosts"] = worst
        return rep

    def hosts_list(self, q):
        return {"hosts": self.svc.inventory.list_hosts(),
                "watchdog": self.svc.watchdog.status()}

    def host_detail_ep(self, q):
        try:
            hid = int(q.get("id", ["0"])[0])
        except ValueError:
            return (400, {"error": "нужен числовой id"})
        d = self.svc.inventory.host_detail(hid)
        if d.get("error"):
            return (404, d)
        d["software"] = self.svc.softwareinv.for_host(hid, 200)
        d["karma_hist"] = self.svc.inventory.karma_history(hid)
        return d

    def software_search(self, q):
        term = q.get("q", [""])[0]
        return {"results": self.svc.softwareinv.search(term),
                "stats": self.svc.softwareinv.stats()}

    def inv_report(self, q):
        body = self._read_body()
        try:
            return self.svc.softwareinv.receive_report(body)
        except Exception as e:
            return (500, {"ok": False, "error": str(e)})

    def gpo_script(self, q, handler=None):
        """Отдаёт GPO-скрипт. Вызывается двумя путями: напрямую из do_GET
        (с handler) и через роутер — во втором случае файл уже не шлём."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "gpo", "inventory.ps1")
        if handler is None:
            return {"error": "внутренний вызов без handler"}
        if not os.path.isfile(path):
            self._send_json({"error": "скрипт не найден"}, 404)
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            self._send_json({"error": "не читается"}, 500)
            return
        handler.send_response(200)
        handler.send_header("Content-Type",
                            "text/plain; charset=utf-8")
        handler.send_header("Content-Length", str(len(data)))
        handler.send_header(
            "Content-Disposition",
            'attachment; filename="netpulse-inventory.ps1"')
        handler.end_headers()
        try:
            handler.wfile.write(data)
        except BrokenPipeError:
            pass

    # ----- плановые работы -----

    def planner_list(self, q):
        return {"tasks": self.svc.planner.status_list(),
                "enabled": bool(self.cfg.get("planner", {}).get("enabled"))}

    def planner_done(self, q):
        body = self._read_body()
        name = str(body.get("name") or "").strip()
        return self.svc.planner.mark_done(name,
                                          actor=str(body.get("actor")
                                                    or "admin"))

    def events_feed(self, q):
        limit = min(int(q.get("limit", ["80"])[0] or 80), 300)
        hid = q.get("host_id", [None])[0]
        if hid:
            try:
                hid = int(hid)
            except ValueError:
                hid = None
        return {"events": self.svc.inventory.recent_events(limit, hid)}

    def health_recompute(self, q):
        return self.svc.inventory.recompute_health()

    def watchdog_poll(self, q):
        job_id = submit_job(self.svc.watchdog.poll_cycle)
        deadline = time.time() + 240
        while time.time() < deadline:
            j = JOBS.get(job_id, {})
            if j.get("status") != "running":
                return j.get("result") if j.get("status") == "done" \
                    else {"error": j.get("error")}
            time.sleep(1.5)
        return (504, {"error": "обход превысил таймаут"})

    def runbooks_list(self, q):
        return {"runbooks": self.svc.runbooks.list(),
                "log": self.svc.runbooks.recent_log(20)}

    def runbook_exec(self, q):
        body = self._read_body()
        rb = str(body.get("name") or "").strip()
        params = body.get("params") if isinstance(body.get("params"), dict) \
            else {}
        actor = str(body.get("actor") or "admin")
        res = self.svc.runbooks.execute(rb, params, actor)
        code = 200 if res.get("ok") else 400
        return (code, res)

    def backup_status_list(self, q):
        return {"backups": self.svc.backupwatch.status_list(),
                "enabled": bool(self.cfg.get("backupwatch", {})
                                .get("enabled"))}

    def backup_check_now(self, q):
        job_id = submit_job(self.svc.backupwatch.check_once)
        deadline = time.time() + 120
        while time.time() < deadline:
            j = JOBS.get(job_id, {})
            if j.get("status") != "running":
                return j.get("result") if j.get("status") == "done" \
                    else {"error": j.get("error")}
            time.sleep(1)
        return (504, {"error": "проверка превысила таймаут"})

    # ----- действия на машине -----

    def disk_forecast_ep(self, q):
        return {"forecasts": self.svc.watchdog.disk_forecast()}

    def wol_wake(self, q):
        body = self._read_body()
        return self.svc_wol().wake(body.get("host"))

    def rdp_download(self, q, handler):
        host = (q.get("host", [""])[0] or "").strip()
        if not SAFE_TARGET.match(host):
            self._send_json({"error": "некорректный хост"}, 400)
            return
        content = (
            "screen mode id:i:2\r\n"
            f"full address:s:{host}\r\n"
            "username:s:\r\n"
            "compression:i:1\r\n"
            "audiomode:i:0\r\n"
        )
        data = content.encode("utf-16-le")
        handler.send_response(200)
        handler.send_header("Content-Type", "application/x-rdp")
        handler.send_header("Content-Length", str(len(data)))
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", host)[:40]
        handler.send_header(
            "Content-Disposition",
            f'attachment; filename="{safe or "session"}.rdp"')
        handler.end_headers()
        try:
            handler.wfile.write(data)
        except BrokenPipeError:
            pass

    def svc_wol(self):
        from .wol import WolController
        if not hasattr(self, "_wol"):
            self._wol = WolController(self.svc)
        return self._wol

    # ----- служебное -----

    def _read_body(self):
        body = getattr(self, "_cached_body", None)
        return body if isinstance(body, dict) else {}


ROUTES_GET = {
    "state": "state", "history": "history", "dbhistory": "db_history",
    "interfaces": "interfaces", "connections": "connections",
    "topprocesses": "top_processes",
    "apps": "apps", "appnewconn": "app_new_connections",
    "appexe": "app_exe",
    "idsfeed": "ids_feed", "firewallrules": "firewall_rules",
    "ping": "ping_probe", "trace": "trace", "traceall": "trace_targets",
    "dnsbest": "dns_best", "dnsresolve": "dns_resolve",
    "speedtest": "speedtest", "uploadtest": "speedtest_upload",
    "speedlog": "speedtest_log",
    "mtrstats": "mtr_stats", "landevices": "lan_devices",
    "capturestate": "capture_state",
    "securityresult": "security_result",
    "alerts": "alerts", "ai": "ai_stats",
    "settings": "settings_get", "backuplist": "backup_list",
    "journal": "journal_list", "journalreport": "journal_report",
    "hosts": "hosts_list", "hostdetail": "host_detail_ep",
    "events": "events_feed", "runbooks": "runbooks_list",
    "backupstatus": "backup_status_list",
    "planner": "planner_list", "softsearch": "software_search",
    "gposcript": "gpo_script", "diskforecast": "disk_forecast_ep",
}
ROUTES_POST = {
    "settings": "settings_post",
    "alertsack": "alerts_ack", "aitrain": "ai_train",
    "securityscan": "security_scan", "mtrstart": "mtr_start",
    "mtrstop": "mtr_stop", "lanscan": "lan_scan",
    "portscan": "port_scan", "capturestart": "capture_start",
    "capturestop": "capture_stop",
    "fwblockip": "firewall_block_ip", "fwblockapp": "firewall_block_app",
    "fwunblock": "firewall_unblock",
    "backuprun": "backup_run",
    "journaladd": "journal_add", "journaldel": "journal_delete",
    "runbookexec": "runbook_exec", "watchdogpoll": "watchdog_poll",
    "healthrecompute": "health_recompute", "backupcheck": "backup_check_now",
    "plannerdone": "planner_done", "invreport": "inv_report",
    "wol": "wol_wake", "lanalias": "lan_alias",
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    api: Api = None
    server_version = f"NetPulse/{__version__}"

    def log_message(self, fmt, *args):
        pass

    # ---------- auth ----------

    def _authed(self, qs=None):
        if not self.api.cfg.get("web_auth_enabled"):
            return True
        token = self.api.cfg.get("web_token", "")
        if not token:
            return True
        header = self.headers.get("X-Auth", "")
        if hmac.compare_digest(header.encode("utf-8"), token.encode("utf-8")):
            return True
        cookie = self.headers.get("Cookie", "")
        m = re.search(r"(?:^|;\s*)np_token=([^\s;]+)", cookie)
        if m and hmac.compare_digest(m.group(1).encode("utf-8"), token.encode("utf-8")):
            return True
        if qs:
            qtoken = qs.get("token", [""])[0]
            if qtoken and hmac.compare_digest(qtoken.encode("utf-8"),
                                              token.encode("utf-8")):
                return True
        return False

    # ---------- ответы ----------

    def _send_json(self, obj, code=200):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, path, download_name=None):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            self._send_json({"error": "not found"}, 404)
            return
        ext = os.path.splitext(path)[1].lower()
        ctype = MIME.get(ext, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if ext in (".js", ".css", ".html"):
            self.send_header("Cache-Control", "no-cache")
        if download_name:
            self.send_header("Content-Disposition",
                             f'attachment; filename="{download_name}"')
        self.end_headers()
        self.wfile.write(data)

    def _static(self, rel):
        rel = unquote(rel).lstrip("/")
        full = os.path.normpath(os.path.join(WEB_DIR, rel))
        if not full.startswith(os.path.normpath(WEB_DIR)):
            self._send_json({"error": "forbidden"}, 403)
            return
        if not os.path.isfile(full):
            self._static("index.html")
            return
        self._send_file(full)

    # ---------- GET ----------

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        if path.startswith("/api/") or path == "/metrics":
            if not self._authed(qs):
                self._send_json({"error": "unauthorized"}, 401)
                return

        if path == "/":
            self._static("index.html")
            return

        if path == "/metrics":
            self._prometheus()
            return

        if path == "/api/stream":
            name = "stream"
            self.api.stream(qs, self)
            return

        if path == "/api/rdp":
            self.api.rdp_download(qs, self)
            return

        if path == "/api/gposcript":
            self.api.gpo_script(qs, self)
            return

        if path.startswith("/api/"):
            name = path[len("/api/"):]
            handler_name = ROUTES_GET.get(name)
            if not handler_name:
                self._send_json({"error": "unknown endpoint"}, 404)
                return
            try:
                result = getattr(self.api, handler_name)(qs)
                if isinstance(result, tuple):
                    self._send_json(result[1], result[0])
                else:
                    self._send_json(result)
            except BrokenPipeError:
                pass
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        if path == "/journal.txt":
            try:
                days = min(max(int(qs.get("days", ["30"])[0] or 30), 1), 365)
            except ValueError:
                days = 30
            try:
                body = platform_report_text(self.api.svc, days)
                self.send_response(200)
                self.send_header("Content-Type",
                                 "text/plain; charset=utf-8")
                self.send_header("Content-Length",
                                 str(len(body.encode("utf-8"))))
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="netpulse_otchet_{days}d.txt"')
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        if path == "/report.txt":
            try:
                data = self.api.report_data({})
                lines = [
                    "=" * 56,
                    f"NETPULSE ОТЧЁТ  ({data['generated'][:19]})",
                    "=" * 56,
                    "",
                    f"Качество связи : {data['live']['quality']['label']} "
                    f"({data['live']['quality']['score']}/100)",
                    f"Скорость       : down {data['live']['down_kbps']} KB/s | "
                    f"up {data['live']['up_kbps']} KB/s",
                    f"Пинг           : {data['live']['ping']['current']} ms "
                    f"(джиттер {data['live']['ping']['jitter']}, "
                    f"потери {data['live']['ping']['loss_pct']}%)",
                    f"Квота день     : {data['quota'].get('daily_used_mb')} MB "
                    f"/ {data['quota'].get('daily_limit_mb') or 'без лимита'} MB",
                    f"За 24ч         : avg "
                    f"{round((data['day_stats'].get('avg_kbps') or 0), 1)} KB/s, пик "
                    f"{round((data['day_stats'].get('max_kbps') or 0), 0)} KB/s",
                    "",
                    "Последние алерты:",
                ]
                for a in data["recent_alerts"][:15]:
                    lines.append(f"  [{a['timestamp'][:19]}] {a['type']}: {a['message']}")
                body = "\n".join(lines).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Disposition",
                                 'attachment; filename="netpulse_report.txt"')
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        self._static(path)

    def _prometheus(self):
        s = self.api.svc.get_snapshot()
        lines = [
            "# HELP np_down_speed Current download speed KB/s",
            "# TYPE np_down_speed gauge",
            f"np_down_speed {s['down_kbps']}",
            "# HELP np_up_speed Current upload speed KB/s",
            "# TYPE np_up_speed gauge",
            f"np_up_speed {s['up_kbps']}",
            "# HELP np_ping_ms Current ping ms",
            "# TYPE np_ping_ms gauge",
            f"np_ping_ms {s['ping']['current'] or 0}",
            "# HELP np_quality_score Network quality score 0-100",
            "# TYPE np_quality_score gauge",
            f"np_quality_score {s['quality']['score']}",
            "# HELP np_alerts_unread Unacknowledged alerts",
            "# TYPE np_alerts_unread gauge",
            f"np_alerts_unread {s['alerts_unread']}",
            "# HELP np_traffic_total_mb Session totals MB",
            "# TYPE np_traffic_total_mb counter",
            f"np_traffic_total_down_mb {s['total_down_mb']}",
            f"np_traffic_total_up_mb {s['total_up_mb']}",
        ]
        try:
            j24 = self.api.svc.db.execute(
                """SELECT COUNT(*) AS n FROM journal
                   WHERE timestamp > datetime('now','localtime','-1 day')""",
                fetch=True)
            hosts_n = self.api.svc.db.execute(
                "SELECT COUNT(*) AS n FROM hosts", fetch=True)
            lines += [
                "# HELP np_journal_entries_24h Journal entries last 24h",
                "# TYPE np_journal_entries_24h gauge",
                f"np_journal_entries_24h {(j24[0]['n'] if j24 else 0) or 0}",
                "# HELP np_hosts_total Known machines",
                "# TYPE np_hosts_total gauge",
                f"np_hosts_total {(hosts_n[0]['n'] if hosts_n else 0) or 0}",
            ]
        except Exception:
            pass
        body = "\n".join(lines).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---------- POST ----------

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)
        if not path.startswith("/api/"):
            self._send_json({"error": "unknown endpoint"}, 404)
            return
        if not self._authed(qs):
            self._send_json({"error": "unauthorized"}, 401)
            return

        name = path[len("/api/"):]
        length = int(self.headers.get("Content-Length") or 0)
        body = {}
        if length:
            try:
                raw = self.rfile.read(length)
                body = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                body = {}

        handler_name = ROUTES_POST.get(name)
        if not handler_name:
            self._send_json({"error": "unknown endpoint"}, 404)
            return

        self.api._cached_body = body
        try:
            result = getattr(self.api, handler_name)(qs)
            if isinstance(result, tuple):
                self._send_json(result[1], result[0])
            else:
                self._send_json(result)
        except BrokenPipeError:
            pass
        except Exception as e:
            self._send_json({"error": str(e)}, 500)


def build_server(service: MonitorService, config, backup: BackupManager,
                 host="127.0.0.1", port=8770):
    Handler.api = Api(service, config, backup)
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    return httpd


def run(config):
    service = MonitorService(config)
    backup_mgr = BackupManager(config)
    port = int(config.get("web_port", 8770))

    service.start()
    if config.get("backup", {}).get("enabled"):
        backup_mgr.start()

    httpd = build_server(service, config, backup_mgr, port=port)
    url = f"http://127.0.0.1:{port}"
    print(f"[netpulse] дашборд: {url}")

    def _open():
        try:
            webbrowser_open(url)
        except Exception:
            pass
    threading.Timer(0.9, _open).start()

    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\n[netpulse] остановка...")
    finally:
        try:
            httpd.shutdown()
        except Exception:
            pass
        backup_mgr.stop()
        service.stop()


def webbrowser_open(url):
    import webbrowser
    webbrowser.open(url)
