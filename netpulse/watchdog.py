"""
Сторож парка ПК: периодический опрос машин через PowerShell (локально или
по WinRM Invoke-Command), правила на диск/RAM/EventLog, события в инвентарь.

Ноль внешних зависимостей: только subprocess + powershell.exe.
Конфиг: config.json -> "watchdog": {enabled, interval_min, timeout_sec,
hosts[], disk_free_pct, ram_free_mb, event_ids[], event_hours,
offline_after_polls}.
"""

import json
import logging
import socket
import subprocess
import sys
import threading
from datetime import datetime

from core.utils import decode_process_output

logger = logging.getLogger(__name__)

# Тело скрипта сбора: диски, RAM, аптайм, свежие ошибки System-лога.
# %EH% заменяется на окно часов из конфига.
PS_COLLECT = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$d=Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | "
    "ForEach-Object {[pscustomobject]@{drive=$_.DeviceID;"
    "free=[math]::Round($_.FreeSpace/1GB,1);total=[math]::Round($_.Size/1GB,1)}};"
    "$o=Get-CimInstance Win32_OperatingSystem;"
    "$s=(Get-Date).AddHours(-%EH%);"
    "$e=Get-WinEvent -FilterHashtable @{LogName='System';Level=@(1,2);StartTime=$s} "
    "-MaxEvents 20 | Select-Object -First 10 "
    "@{n='id';e={$_.Id}},"
    "@{n='text';e={($_.Message -split \"`n\")[0]}};"
    "[pscustomobject]@{host=$env:COMPUTERNAME;os=$o.Caption;"
    "ramFreeMB=[math]::Round($o.FreePhysicalMemory/1KB,0);"
    "upDays=[math]::Round(((Get-Date)-$o.LastBootUpTime).TotalDays,1);"
    "disks=$d;errors=$e} | ConvertTo-Json -Depth 3 -Compress"
)


def _now_iso():
    return datetime.now().isoformat()


class ParkWatchdog:
    def __init__(self, service):
        self.svc = service
        self.svc.db.execute(
            """CREATE TABLE IF NOT EXISTS disk_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                host_id INTEGER, drive TEXT,
                free_gb REAL, total_gb REAL)""")
        self.svc.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_diskhist ON disk_history(host_id, drive)")
        self._stop = threading.Event()
        self._fail_streak = {}
        self._thread = None

    # ---------- конфиг ----------

    def _cfg(self):
        base = {
            "enabled": False, "interval_min": 15, "timeout_sec": 25,
            "hosts": ["127.0.0.1"], "disk_free_pct": 10, "ram_free_mb": 500,
            "event_ids": [41, 6008, 7, 153, 7031, 7034], "event_hours": 24,
            "offline_after_polls": 3,
        }
        cfg = dict(self.svc.cfg.get("watchdog", {}) or {})
        base.update(cfg)
        return base

    def _is_local(self, host):
        h = str(host).lower().strip()
        local = ("127.0.0.1", "localhost", "::1", socket.gethostname().lower())
        return h in local

    # ---------- сбор ----------

    def _collect(self, host, timeout_sec):
        body = PS_COLLECT.replace("%EH%", "24")
        if self._is_local(host):
            cmd = ["powershell", "-NoProfile", "-NonInteractive",
                   "-Command", body]
        else:
            cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                   f"Invoke-Command -ComputerName {host} "
                   f"-ScriptBlock {{ {body} }}"]
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout_sec,
                              creationflags=flags)
        out = decode_process_output(proc.stdout or b"")
        out = out.strip()
        if not out:
            raise RuntimeError("пустой ответ")
        data = json.loads(out)
        if isinstance(data, list):
            data = data[0] if data else {}
        return data

    def _apply_rules(self, host, host_id, data):
        inv = self.svc.inventory
        cfg = self._cfg()
        found = []

        for d in (data.get("disks") or []):
            total = float(d.get("total") or 0)
            free = float(d.get("free") or 0)
            if total <= 0:
                continue
            pct = free / total * 100.0
            if pct <= float(cfg["disk_free_pct"]):
                found.append(("disk", "CRITICAL",
                              f"Диск {d.get('drive')} заполнен: свободно "
                              f"{pct:.0f}% ({free} GB)",
                              f"{host}:disk:{d.get('drive')}", 12))

        ram = data.get("ramFreeMB")
        if ram is not None and float(ram) < float(cfg["ram_free_mb"]):
            found.append(("ram", "HIGH",
                          f"Мало памяти: свободно {ram} MB",
                          f"{host}:ram:{datetime.now():%Y%m%d%H}", 2))

        watch_ids = set(int(x) for x in (cfg["event_ids"] or []))
        seen_ids = set()
        for e in (data.get("errors") or []):
            try:
                eid = int(e.get("id") or 0)
            except (ValueError, TypeError):
                continue
            if eid not in watch_ids or eid in seen_ids:
                continue
            seen_ids.add(eid)
            text = (e.get("text") or "").strip()[:160]
            sev = "HIGH" if eid in (41, 6008) else "MEDIUM"
            found.append(("eventlog", sev,
                          f"Event ID {eid}: {text}",
                          f"{host}:ev:{eid}:{datetime.now():%Y%m%d}", 20))

        for kind, sev, text, key, hours in found:
            inv.note_event(host_id, kind, sev, "watchdog", text,
                           dedup_key=key, dedup_hours=hours)
        return len(found)

    def _poll_host(self, host, cfg):
        inv = self.svc.inventory
        timeout_sec = int(cfg.get("timeout_sec", 25))
        try:
            data = self._collect(host, timeout_sec)
        except Exception as e:
            streak = self._fail_streak.get(host, 0) + 1
            self._fail_streak[host] = streak
            if streak >= int(cfg.get("offline_after_polls", 3)):
                hid = inv.resolve_host_id(host)
                if hid:
                    inv.mark_online(hid, False)
                    inv.note_event(
                        hid, "offline", "HIGH", "watchdog",
                        f"Машина недоступна {streak} опросов подряд "
                        f"({str(e)[:80]})",
                        dedup_key=f"{host}:offline:{datetime.now():%Y%m%d}",
                        dedup_hours=6)
            return

        hid = inv.upsert_host(data.get("host") or host,
                              ip=(host if not self._is_local(host) else "127.0.0.1"),
                              os_info=str(data.get("os") or "")[:120])
        if hid:
            inv.mark_online(hid, True)
        if self._fail_streak.get(host, 0) > 0:
            inv.note_event(hid, "online", "LOW", "watchdog",
                           "Снова в сети", dedup_key=f"{host}:online:"
                           f"{datetime.now():%Y%m%d}", dedup_hours=6)
        self._fail_streak[host] = 0
        problems = self._apply_rules(host, hid, data) if hid else 0
        if hid:
            self._record_disks(hid, data.get("disks") or [])
        logger.debug("Сторож: %s ок (проблем: %s)", host, problems)

    def _record_disks(self, host_id, disks):
        rows = []
        for d in disks or []:
            try:
                rows.append(((_now_iso()), host_id, str(d.get("drive")),
                             float(d.get("free") or 0),
                             float(d.get("total") or 0)))
            except (ValueError, TypeError):
                continue
        if rows:
            self.svc.db.execute_many(
                """INSERT INTO disk_history
                   (timestamp, host_id, drive, free_gb, total_gb)
                   VALUES (?,?,?,?,?)""", rows)

    def poll_cycle(self):
        """Один обход всего списка. Вызывается по расписанию или вручную."""
        cfg = self._cfg()
        hosts = [h.strip() for h in (cfg.get("hosts") or []) if str(h).strip()]
        for host in hosts[:60]:
            if self._stop.is_set():
                break
            try:
                self._poll_host(host, cfg)
            except Exception as e:
                logger.warning("Сторож: сбой по %s: %s", host, e)
        try:
            self.svc.db.execute(
                """DELETE FROM disk_history
                   WHERE timestamp < datetime('now','localtime','-180 days')""")
            self.svc.inventory.recompute_health()
        except Exception as e:
            logger.warning("Карма не пересчитана: %s", e)
        return {"ok": True, "polled": len(hosts)}

    def disk_forecast(self, window_days=21, horizon_days=90):
        """Прогноз заполнения: по наклону свободного места за окно."""
        rows = self.svc.db.execute(
            """SELECT h.name AS host, dh.drive,
                      MIN(dh.timestamp) AS t0, MAX(dh.timestamp) AS t1,
                      (SELECT free_gb FROM disk_history x
                       WHERE x.host_id = dh.host_id AND x.drive = dh.drive
                       ORDER BY id DESC LIMIT 1) AS free_now
               FROM disk_history dh JOIN hosts h ON h.id = dh.host_id
               WHERE dh.timestamp > datetime('now','localtime', ? || ' days')
               GROUP BY dh.host_id, dh.drive""",
            (f"-{max(7, int(window_days))}",), fetch=True) or []

        out = []
        for r in rows:
            pair = self.svc.db.execute(
                """SELECT free_gb, timestamp FROM disk_history
                   WHERE host_id = (SELECT id FROM hosts WHERE name = ?)
                     AND drive = ?
                   ORDER BY timestamp LIMIT 2""",
                (r["host"], r["drive"]), fetch=True)
            if not pair or len(pair) < 2:
                continue
            first_free = float(pair[0]["free_gb"] or 0)
            last_free = float(r["free_now"] or 0)
            try:
                span_days = max(0.5, (datetime.fromisoformat(r["t1"])
                                      - datetime.fromisoformat(pair[0]["timestamp"])
                                      ).total_seconds() / 86400.0)
            except Exception:
                continue
            if span_days < 0.75:
                continue
            slope = (last_free - first_free) / span_days  # GB в день
            if slope >= -0.02:
                continue  # не убывает или почти статичен
            days_left = int(last_free / (-slope))
            if days_left > horizon_days:
                continue
            out.append({"host": r["host"], "drive": r["drive"],
                        "free_gb": round(last_free, 1),
                        "rate_gb_day": round(slope, 2),
                        "days_left": days_left})
        return sorted(out, key=lambda x: x["days_left"])

    # ---------- жизненный цикл ----------

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop():
            interval = max(5, int(self._cfg().get("interval_min", 15))) * 60
            while not self._stop.wait(5):
                try:
                    self.poll_cycle()
                except Exception as e:
                    logger.warning("Цикл сторожа: %s", e)
                self._stop.wait(interval)

        self._thread = threading.Thread(target=loop, daemon=True,
                                        name="np-watchdog")
        self._thread.start()
        logger.info("Сторож парка запущен")

    def stop(self):
        self._stop.set()

    def status(self):
        cfg = self._cfg()
        return {
            "enabled": bool(cfg["enabled"]),
            "interval_min": cfg["interval_min"],
            "hosts": cfg["hosts"],
            "running": bool(self._thread and self._thread.is_alive()),
        }
