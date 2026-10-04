"""Живой MTR (PingPlotter/WinMTR идея): циклы ping с TTL по хопам.

v3-реализация: тот же контракт MTREngine(service), типизировано.
service обязан давать .cfg (dict); опционально .db/.push_alert.
"""
from __future__ import annotations

import logging
import re
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.utils import decode_process_output, parse_trace_output

logger = logging.getLogger(__name__)

_MS_TIMES_RE = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*(?:мс|ms)",
                          re.IGNORECASE)


def ms_times(output: str) -> List[float]:
    return [float(t.replace(",", ".")) for t in _MS_TIMES_RE.findall(output or "")]


def _now_iso() -> str:
    return datetime.now().isoformat()


class MTREngine:
    def __init__(self, service: Any):
        self.svc = service
        self.target: Optional[str] = None
        self.hops: List[Dict[str, Any]] = []
        self.running = False
        self.cycles_done = 0
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.RLock()

    def start(
        self,
        target: Optional[str] = None,
        max_hops: Optional[int] = None,
        cycle_sec: Optional[float] = None,
        pings_per_hop: Optional[int] = None,
    ) -> None:
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
        self._thread = threading.Thread(
            target=self._loop,
            args=(target, max_hops, cycle_sec, pings_per_hop),
            daemon=True, name="np-mtr")
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=15)

    def _loop(
        self, target: str, max_hops: int, cycle_sec: float, pings_per_hop: int
    ) -> None:
        while self.running and not self._stop.is_set():
            reached = False
            for hop_rec in self.hops[:max_hops]:
                if not self.running:
                    break
                ttl = hop_rec["hop"]
                cmd = (["ping", "-n", str(pings_per_hop), "-i", str(ttl),
                        "-w", "900", target] if sys.platform == "win32"
                       else ["ping", "-c", str(pings_per_hop), "-t", str(ttl),
                             "-W", "1", target])
                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, timeout=pings_per_hop * 2 + 4,
                        creationflags=subprocess.CREATE_NO_WINDOW
                        if sys.platform == "win32" else 0)
                    out = decode_process_output(proc.stdout + proc.stderr)
                except Exception:
                    out = ""

                hop_ip, _first_ms = parse_trace_output(out, target=target)
                if hop_ip != "*" and hop_ip != "?":
                    hop_rec["ip"] = hop_ip

                times = ms_times(out)
                hop_answered = hop_ip not in ("*", "?")
                if times:
                    for msv in times:
                        hop_rec["samples"].append((True, msv))
                elif hop_answered:
                    # Хоп ответил «TTL превышен» без поля времени (Windows) —
                    # это ОТВЕТ, а не потеря; латентность промежуточного хопа
                    # так не измерить, но потери считаем честно.
                    hop_rec["samples"].append((True, None))
                else:
                    hop_rec["samples"].append((False, None))

                if hop_ip == target:
                    reached = True
                    break

            with self._lock:
                self.cycles_done += 1
            self._stop.wait(cycle_sec if not reached else max(2, cycle_sec / 2))

    def stats(self) -> Dict[str, Any]:
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

    def save_snapshot(self) -> None:
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
            now = _now_iso()
            self.svc.db.execute_many(
                "INSERT INTO mtr_history (ts, target, hop, ip, loss_pct, avg_ms) "
                "VALUES (?,?,?,?,?,?)",
                [(now, st["target"], h["hop"], h["ip"], h["loss_pct"], h["avg_ms"])
                 for h in st["hops"]])
        except Exception as e:
            logger.debug("mtr snapshot: %s", e)

    def schedule_loop(self) -> None:
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
