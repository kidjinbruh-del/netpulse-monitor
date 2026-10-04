"""Пер-процессный монитор + IDS.

Активность процессов в сети: соединения, новые эндпоинты, I/O-прокси.
IDS: детект скана портов одним IP и стука на подозрительные порты.

v3-реализация: тот же контракт ProcessMonitor(service), типизировано.
service обязан давать .cfg (dict); опционально .push_alert.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional

import psutil

logger = logging.getLogger(__name__)

SUSPICIOUS_ALERT_RATE_SEC = 300


class ProcessMonitor:
    def __init__(self, service: Any):
        self.svc = service
        self._lock = threading.RLock()
        self._seen_endpoints: Dict[tuple, float] = {}  # (pid, ip:port) -> ts
        self._scan_window: Dict[str, set] = defaultdict(set)  # rip -> set(port)
        self._last_alert: Dict[str, float] = defaultdict(float)
        self._io_last: Dict[int, int] = {}             # pid -> io bytes total
        self.processes: Dict[int, Dict[str, Any]] = {}
        self.new_events: Deque[Dict[str, Any]] = deque(maxlen=150)
        self.ids_events: Deque[Dict[str, Any]] = deque(maxlen=150)

    def _ids_cfg(self):
        cfg = self.svc.cfg
        return {
            "window": float(cfg.get("ids", {}).get("window_sec", 120)),
            "suspicious_ports": set(
                cfg.get("security", {}).get("suspicious_ports", [])),
            "scan_threshold": int(
                cfg.get("security", {}).get("scan_detection_threshold", 15)),
            "ids_on": bool(cfg.get("ids", {}).get("enabled", True)),
            "whitelist": cfg.get("ids", {}).get("whitelist") or [],
        }

    def sample(self) -> None:
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
        icfg = self._ids_cfg()
        window = icfg["window"]
        suspicious_ports = icfg["suspicious_ports"]
        scan_threshold = icfg["scan_threshold"]
        ids_on = icfg["ids_on"]

        per_pid: Dict[int, Dict[str, int]] = defaultdict(
            lambda: {"conns": 0, "est": 0})
        seen_now: Dict[tuple, float] = {}
        events: List[Dict[str, Any]] = []

        for c in raw:
            pid = c.pid or 0
            per_pid[pid]["conns"] += 1
            if c.status == "ESTABLISHED":
                per_pid[pid]["est"] += 1
            if not c.raddr:
                continue
            key = (pid, f"{c.raddr.ip}:{c.raddr.port}")
            seen_now[key] = now

            if key not in self._seen_endpoints \
                    and c.status in ("ESTABLISHED", "SYN_SENT"):
                pname = pid_names.get(pid, "?")
                events.append({
                    "ts": now, "pid": pid, "process": pname,
                    "remote": f"{c.raddr.ip}:{c.raddr.port}",
                    "local_port": c.laddr.port if c.laddr else 0,
                    "suspicious": c.raddr.port in suspicious_ports,
                })
                if ids_on and not c.raddr.ip.startswith(("127.", "::1")):
                    self._check_port_scan(
                        c.raddr.ip, c.raddr.port, window, scan_threshold)
                    if c.raddr.port in suspicious_ports:
                        self._check_suspicious_conn(
                            pid, pname, c.raddr.ip, c.raddr.port,
                            icfg["whitelist"], now)

        # Чистка окон.
        cutoff = now - max(window * 3, 300)
        self._seen_endpoints = {k: v for k, v in self._seen_endpoints.items()
                                if v > cutoff}
        self._seen_endpoints.update(seen_now)

        # I/O прокси по процессам (дельта суммарных IO-байтов).
        io_rates = self._sample_io(per_pid)

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

    def _sample_io(self, per_pid: Dict[int, Dict[str, int]]) -> Dict[int, float]:
        io_rates: Dict[int, float] = {}
        alive_pids = set(per_pid.keys()) | set(self._io_last.keys())
        for pid in list(alive_pids)[:400]:
            try:
                io = psutil.Process(pid).io_counters()
                total = io.read_bytes + io.write_bytes
                last = self._io_last.get(pid)
                self._io_last[pid] = total
                if last is not None:
                    delta = max(0, total - last)
                    if delta > 512:
                        io_rates[pid] = delta / 1024.0
            except Exception:
                self._io_last.pop(pid, None)
        return io_rates

    def _check_port_scan(
        self, rip: str, rport: int, window: float, scan_threshold: int
    ) -> None:
        self._scan_window[rip].add(rport)
        if len(self._scan_window[rip]) >= scan_threshold:
            self._raise_ids(
                "PORT_SCAN",
                f"Скан портов с {rip}: "
                f"{len(self._scan_window[rip])} разных целей за {window:.0f}с")
            self._scan_window[rip].clear()

    def _check_suspicious_conn(
        self, pid: int, pname: str, rip: str, rport: int,
        whitelist: list, now: float,
    ) -> None:
        # whitelist IDS: {"process": "mstsc.exe", "ports": "3389"}
        for rule in whitelist:
            if not isinstance(rule, dict):
                continue
            proc_ok = (not rule.get("process")
                       or str(rule["process"]).lower() in str(pname).lower())
            ports_ok = True
            if rule.get("ports"):
                try:
                    ports_ok = int(rport) in [
                        int(x) for x in
                        str(rule["ports"]).replace(" ", "").split(",")
                        if x]
                except (ValueError, TypeError):
                    ports_ok = True
            if proc_ok and ports_ok:
                return
        rl_key = f"sus:{rip}:{rport}"
        if now - self._last_alert[rl_key] > SUSPICIOUS_ALERT_RATE_SEC:
            self._last_alert[rl_key] = now
            self._raise_ids(
                "SUSPICIOUS_CONN",
                f"{pname} (PID {pid}) подключился к подозрительному порту "
                f"{rip}:{rport}")

    def _raise_ids(self, alert_type: str, message: str) -> None:
        with self._lock:
            dup = any(e["type"] == alert_type and e["message"] == message
                      for e in list(self.ids_events)[-10:])
            self.ids_events.appendleft({"ts": time.time(), "type": alert_type,
                                        "message": message})
        if not dup:
            try:
                self.svc.push_alert(alert_type, message, "ids")
            except Exception:
                pass

    def top_io(self, limit: int = 15) -> List[Dict[str, Any]]:
        with self._lock:
            procs = sorted(self.processes.values(),
                           key=lambda p: (-p["io_kbps"], -p["est"]))[:limit]
        return procs

    def new_connections(self, limit: int = 80) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.new_events)[:limit]

    def ids_feed(self, limit: int = 80) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.ids_events)[:limit]
