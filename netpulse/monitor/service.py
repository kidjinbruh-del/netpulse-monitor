"""MonitorService — единый источник живого состояния.

- трафик суммарно и по интерфейсам (psutil)
- пинг-монитор + интегральное качество связи
- пер-процессная сетевая активность, события новых соединений
- IDS: детект сканов портов и подозрительных подключений
- квоты трафика (день/месяц), системные метрики
- AI-анализ тиков с прогнозом и объяснением аномалий (z-score)
- запись истории в SQLite

v3-реализация: тот же контракт и поведение 1:1, типизировано.
config — legacy flat-dict (см. config.legacy_export.to_legacy_dict).
"""
from __future__ import annotations

import copy
import json
import logging
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional

import psutil

from ai import AIOrchestrator
from core import DatabaseManager, Pinger

from netpulse.backupwatch import BackupWatch
from netpulse.cve import CVEChecker
from netpulse.customchecks import CustomChecks
from netpulse.healing import Healing
from netpulse.infra import Infra
from netpulse.inventory import Inventory
from netpulse.journal import WorkJournal
from netpulse.l2map import L2Map
from netpulse.geo import top_countries
from netpulse.planner import Planner
from netpulse.proxmox import ProxmoxClient
from netpulse.runbooks import RunbookRunner
from netpulse.softwareinv import SoftwareInventory
from netpulse.watchdog import ParkWatchdog
from .capture import RawCaptureService
from .lanscan import LANNetworkScanner
from .mtr import MTREngine
from .procmon import ProcessMonitor
from .quality import _is_admin, _now_iso, quality_label, quality_score
from .quota import QuotaManager

logger = logging.getLogger(__name__)


class MonitorService:
    def __init__(self, config: Dict[str, Any]):
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

        # Платформа отдела: журнал, парк, сторожа, кнопки.
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
        self._threads: List[threading.Thread] = []

        self._psutil_last: Optional[dict] = None
        self.history: Deque[tuple] = deque(maxlen=1800)
        self._ram_hist: Deque[tuple] = deque(maxlen=120)
        self.live_alerts: Deque[Dict[str, Any]] = deque(maxlen=60)
        self._alert_rl: Dict[str, float] = {}
        self._cached_state_json = "{}"
        self._cached_state_ts = 0.0

        self.snapshot: Dict[str, Any] = {
            "ts": time.time(),
            "down_kbps": 0.0, "up_kbps": 0.0, "total_kbps": 0.0,
            "total_down_mb": 0.0, "total_up_mb": 0.0, "max_kbps": 0.0,
            "pernic": {},
            "ping": {"current": None, "jitter": 0.0, "loss_pct": 0.0,
                     "min": 0.0, "max": 0.0},
            "quality": {"score": 100.0, "label": "Отлично", "color": "#22d3a7"},
            "system": {"cpu": 0.0, "mem_pct": 0.0, "mem_used_gb": 0.0,
                       "mem_total_gb": 0.0},
            "uptime_sec": 0,
            "mode": {"traffic": "psutil", "admin": False},
            "alerts_unread": 0,
        }
        self._tick = 0

    def _ensure_tables(self) -> None:
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
            logger.info("[db] таблицы NetPulse: %s", e)

    # ---------- жизненный цикл ----------

    def start(self) -> None:
        self.pinger.start()
        if self.cfg.get("ai", {}).get("enabled", True):
            try:
                hist = self._training_provider()
                if hist and len(hist) >= 10:
                    self.ai.train_model(hist)
            except Exception as e:
                logger.info("[ai] стартовое обучение: %s", e)
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

            # L2-карта: редкий опрос портов коммутаторов после автоскана.
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
        logger.info("[netpulse] мониторинг запущен (админ: %s)",
                    "да" if admin else "нет")

    def stop(self) -> None:
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

    def _traffic_loop(self) -> None:
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
                logger.info("[traffic] %s", e)
            self._stop_event.wait(1)

    def _tick_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                pstats = self.pinger.get_stats()
                ping_ms = pstats.get("current")
                jitter = float(pstats.get("jitter") or 0)
                loss = float(pstats.get("loss") or 0)

                score = quality_score(ping_ms, jitter, loss,
                                      self.cfg.get("quality", {}))
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
                    snap["quality"] = {"score": score, "label": label,
                                       "color": color}
                    snap["uptime_sec"] = int(time.time() - self.started_at)
                    snap["system"] = {
                        "cpu": round(cpu, 1),
                        "mem_pct": round(vm.percent, 1),
                        "mem_used_gb": round((vm.total - vm.available)
                                             / 1073741824, 2),
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
                                f"Аномалия ({analysis.get('confidence', 0):.2f}): "
                                f"{explanation}",
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
                            self.snapshot["alerts_unread"] = (
                                row[0]["n"] if row else 0) or 0
                    except Exception:
                        pass
                    self._build_state_cache()
            except Exception as e:
                logger.info("[tick] %s", e)
            self._stop_event.wait(1)

    def _procmon_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.procmon.sample()
            except Exception as e:
                logger.info("[procmon] %s", e)
            self._stop_event.wait(2)

    def _cleanup_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(3600)
            try:
                self.db.cleanup_old_records(self.cfg.get("db_cleanup_days", 30))
            except Exception as e:
                logger.info("[cleanup] %s", e)

    # ---------- кэш состояния для SSE ----------

    def _build_state_cache(self) -> None:
        payload = json.dumps(self.get_snapshot(), ensure_ascii=False)
        with self._lock:
            self._cached_state_json = payload
            self._cached_state_ts = time.time()

    def state_json_cached(self) -> str:
        if time.time() - self._cached_state_ts > 1.5:
            self._build_state_cache()
        with self._lock:
            return self._cached_state_json

    # ---------- данные ----------

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self.snapshot)

    def get_history(self, seconds: int = 300) -> list:
        cutoff = time.time() - seconds
        with self._lock:
            return [h for h in self.history if h[0] >= cutoff]

    def forecast_speed(self) -> Optional[Dict[str, Any]]:
        """Линейный прогноз скорости на 5 минут вперёд."""
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

    def _explain_anomaly(self) -> str:
        """Объяснение аномалии z-оценками фич относительно последних минут."""
        pts = self.get_history(600)
        if len(pts) < 30:
            return ""
        downs = [p[1] for p in pts]
        ups = [p[2] for p in pts]
        cur_down, cur_up = downs[-1], ups[-1]

        parts = []

        def zscore(series, val):
            mean = sum(series[:-1]) / max(len(series) - 1, 1)
            var = sum((x - mean) ** 2 for x in series[:-1]) / max(
                len(series) - 1, 1)
            std = var ** 0.5 or 1
            return (val - mean) / std

        zd, zu = zscore(downs, cur_down), zscore(ups, cur_up)
        if zd > 2.5:
            parts.append(f"всплеск загрузки ×{zd:.1f}σ ({cur_down:.0f} KB/s)")
        if zu > 2.5:
            parts.append(f"всплеск отдачи ×{zu:.1f}σ ({cur_up:.0f} KB/s)")
        return "; ".join(parts) if parts else ""

    def db_history(self, hours: int = 24) -> list:
        fmt = "%Y-%m-%d %H:%M" if hours <= 6 else "%Y-%m-%d %H"
        window = f"-{int(hours * 60)} minutes"
        rows_t = self.db.execute(
            f"""SELECT strftime('{fmt}', timestamp) AS bucket,
                       AVG(speed) AS kbps, SUM(bytes_in_delta) AS din,
                       SUM(bytes_out_delta) AS dout
                FROM traffic
                WHERE timestamp > datetime('now','localtime', ?)
                GROUP BY bucket ORDER BY bucket""",
            (window,), fetch=True) or []
        rows_p = self.db.execute(
            f"""SELECT strftime('{fmt}', timestamp) AS bucket,
                       AVG(ping_ms) AS ping, AVG(jitter) AS jitter,
                       AVG(loss)*100.0 AS loss
                FROM pings
                WHERE timestamp > datetime('now','localtime', ?)
                GROUP BY bucket ORDER BY bucket""",
            (window,), fetch=True) or []
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

    def connections(
        self, limit: int = 150, include_listening: bool = False
    ) -> Any:
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

    def top_processes_by_conns(self, limit: int = 8) -> list:
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

    def interfaces_info(self) -> Any:
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
            # Один проблемный адаптер не должен ломать весь список.
            try:
                if name.lower().startswith(("loopback", "lo")):
                    continue
                ipv4 = next((a.address for a in addr_list
                             if getattr(a.family, "name", "") == "AF_INET"),
                            None)
                mac = next((a.address for a in addr_list
                            if getattr(a.family, "name", "")
                            in ("AF_LINK", "packet")), "")
                st = stats.get(name)
                info.append({
                    "name": name,
                    "ipv4": ipv4,
                    "mac": mac,
                    "up": bool(getattr(st, "isup", False)) if st else None,
                    "speed_mbps": getattr(st, "speed", 0) or None
                    if st else None,
                    "down_kbps": (live.get(name, {}) or {}).get("down_kbps", 0),
                    "up_kbps": (live.get(name, {}) or {}).get("up_kbps", 0),
                })
            except Exception as e:
                logger.info("[ifaces] %s: %s", name, e)
        return info

    # ---------- алерты ----------

    def push_alert(
        self, alert_type: str, message: str, source: str, rate: int = 0
    ) -> None:
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
            logger.info("[alerts] %s", e)

    def notify_external(self, alert_type: str, message: str) -> None:
        tg = self.cfg.get("telegram", {})
        if tg.get("enabled") and tg.get("token") and tg.get("chat_id"):
            def send_tg():
                try:
                    url = (f"https://api.telegram.org/bot{tg['token']}"
                           f"/sendMessage")
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

        # Generic webhook: Slack/Discord/Mattermost/Teams/свой бэкенд.
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

        # Email (SMTP, stdlib).
        em = self.cfg.get("email") or {}
        if em.get("enabled") and em.get("smtp_host") and em.get("to"):
            def send_mail():
                try:
                    import smtplib
                    from email.mime.text import MIMEText
                    from email.header import Header
                    msg = MIMEText(f"{message}\n\nИсточник: netpulse\n"
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
                    logger.warning("email: %s", e)
            threading.Thread(target=send_mail, daemon=True).start()

    # ---------- сохранение ----------

    def profile_thresholds(self, dtype: Optional[str] = None) -> Optional[dict]:
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

    def _alert_thresholds(self) -> Dict[str, float]:
        q = self.cfg.get("quality", {})
        return {
            "ping_high": q.get("warn_ping_ms", 120) * 1.25,
            "jitter_high": q.get("max_jitter_ms", 15),
            "loss_high": q.get("max_loss_pct", 2),
            "loss_critical": max(5, q.get("max_loss_pct", 2) * 2.5),
        }

    def _save_pings(self, saves: list) -> None:
        self.db.execute_many(
            """INSERT INTO pings (timestamp, ping_ms, loss, jitter, target)
               VALUES (?,?,?,?,?)""",
            [(s["timestamp"], s["ping_ms"], s["loss"], s["jitter"], s["target"])
             for s in saves])

    def _flush_traffic(self) -> None:
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
                (_now_iso(), down + up, td, tu,
                 int(down * 1024 * 5), int(up * 1024 * 5)))

    def _on_ai_alert(self, data: Dict[str, Any]) -> None:
        conf = float(data.get("confidence") or 0)
        self.push_alert(
            "AI_ANOMALY",
            f"Аномалия трафика (уверенность {conf:.2f}): "
            f"{data.get('features', {})}",
            "ai_agent", rate=60)

    def _training_provider(self) -> list:
        traffic = self.db.execute(
            """SELECT timestamp, speed, bytes_in_delta AS bytes_in,
                      bytes_out_delta AS bytes_out
               FROM traffic
               WHERE speed IS NOT NULL
                 AND timestamp > datetime('now','localtime','-3 hours')
               ORDER BY timestamp DESC LIMIT 800""", fetch=True) or []
        pings = self.db.execute(
            """SELECT timestamp, ping_ms, jitter FROM pings
               WHERE ping_ms IS NOT NULL
                 AND timestamp > datetime('now','localtime','-3 hours')
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

    def apply_settings(self, updates: Dict[str, Any]) -> bool:
        from netpulse.config.store import merge_updates, save_config
        merge_updates(self.cfg, updates)
        save_config(self.cfg)
        try:
            self.pinger.set_target(self.cfg.get("ping_target", "8.8.8.8"))
            self.pinger.set_thresholds(self._alert_thresholds())
        except Exception as e:
            logger.warning("apply_settings: пингер не обновлён: %s", e)
        try:
            self.ai.set_enabled(bool(self.cfg.get("ai", {}).get("enabled", True)))
            th = float(self.cfg.get("ai", {}).get("anomaly_threshold", 0.6))
            self.ai.traffic_agent.anomaly_threshold = th
        except Exception as e:
            logger.warning("apply_settings: AI не обновлён: %s", e)
        return True

    # ---------- аналитика: SLA, гео, RAM-прогноз, MTR, отчёты ----------

    def mtr_history(self, hours: int = 24) -> list:
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

    def sla_period(self, days: int = 30) -> list:
        """SLA-доступность узлов за период по hosts + событиям OFFLINE."""
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
            # Грубая оценка: downtime = события OFFLINE без подтверждения ONLINE.
            est = 100.0 - min(100.0, n_off * 5 if n_off else 0)
            out.append({
                "id": h["id"], "name": h["name"], "ip": h["ip"],
                "online": bool(h["online"]),
                "offline_events": n_off, "online_events": n_on,
                "sla_pct": round(max(0.0, est), 2),
                "first_seen": h["first_seen"], "last_seen": h["last_seen"],
            })
        return sorted(out, key=lambda x: x["sla_pct"])

    def geo_attack_map(self, limit: int = 150) -> Dict[str, Any]:
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
        # Отдельно публичные IP из алертов за период.
        rows = self.db.execute(
            """SELECT message FROM alerts
               WHERE alert_type IN ('SUSPICIOUS_CONN','PORT_SCAN','SECURITY_SCAN')
               ORDER BY id DESC LIMIT 300""", fetch=True) or []
        for r in rows:
            for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", r["message"]):
                ips.append(m.group(1))
        return {"countries": top_countries(ips),
                "total_ips": len(ips), "uniq": len(set(ips))}

    def ram_forecast(self, days_left_cap: int = 30) -> Dict[str, Any]:
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
        return {"ok": True, "last_pct": pts[-1][1],
                "slope_pct_pt": round(slope, 3),
                "days_left": int(days_left) if days_left < days_left_cap else None}

    def _ram_history(self) -> list:
        # Из кольцевого буфера mem_pct (пишется раз в секунду в _tick_loop).
        return list(getattr(self, "_ram_hist", None) or [])[-120:]

    def _l2_auto_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.l2map.scan()
            except Exception as e:
                logger.info("[l2] %s", e)
            self._stop_event.wait(1800)

    def _escalate_loop(self) -> None:
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
                logger.info("[escalate] %s", e)
            self._stop_event.wait(600)

    def _weekly_report_loop(self) -> None:
        while not self._stop_event.is_set():
            # Авто-отчёт раз в неделю по расписанию.
            try:
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
                logger.info("[weekly] %s", e)
            self._stop_event.wait(60)

    def _weekly_report_text(self) -> str:
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

    def _send_report_email(self, to: str, text: str) -> None:
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
            logger.warning("week-report email: %s", e)

    def _send_report_webhook(self, url: str, text: str) -> None:
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

    def weekly_report_text_ep(self) -> Dict[str, Any]:
        return {"report": self._weekly_report_text()}
