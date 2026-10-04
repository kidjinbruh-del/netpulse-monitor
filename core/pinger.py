"""Pinger — ICMP ping с буферизацией и порогами алертов.

v3-реализация: тот же контракт Pinger, типизировано.
"""
from __future__ import annotations

import json
import logging
import os
import statistics
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from .utils import decode_process_output, parse_ping_output, safe_kill_process

logger = logging.getLogger(__name__)

CRASH_DUMP_FILE = "emergency_ping_dump.json"
SAVE_INTERVAL_SEC = 5
MAX_BUFFER_SIZE = 1000
LOOP_IDLE_SEC = 1


class Pinger:
    def __init__(
        self,
        target: str = "8.8.8.8",
        alert_thresholds: Optional[Dict[str, float]] = None,
        alert_callback: Optional[Callable[[str, str], None]] = None,
    ):
        self.target = target
        self.running = False
        self._stop_event = threading.Event()
        self._alert_thresholds = alert_thresholds or {}
        self._alert_callback = alert_callback
        self._last_alert_time: Dict[str, float] = {}

        self._data_lock = threading.RLock()
        self._io_lock = threading.RLock()
        self._process_lock = threading.Lock()
        self._thread_lock = threading.Lock()

        self.history: Deque[Tuple[float, Optional[float], bool]] = deque(maxlen=300)
        self.lost_packets = 0
        self.total_packets = 0
        self.current_ping: Optional[float] = None
        self.last_good_ping: Optional[float] = None
        self.min_ping = float("inf")
        self.max_ping = 0.0
        self.jitter = 0.0

        self._pending_saves: List[Dict[str, Any]] = []
        self._save_interval = SAVE_INTERVAL_SEC
        self._last_save_time = 0.0
        self._current_process: Optional[subprocess.Popen] = None
        self._ping_thread: Optional[threading.Thread] = None

        self._db_callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None

        self._recover_from_crash()

    def set_db_callback(self, callback: Callable) -> None:
        """Установка callback для сохранения в БД."""
        self._db_callback = callback

    def set_alert_callback(self, callback: Callable) -> None:
        """Установка callback для алертов."""
        self._alert_callback = callback

    def set_target(self, target: str) -> None:
        """Живая смена цели пинга."""
        if target and target != self.target:
            self.target = target
            logger.info("Цель пинга изменена на %s", target)

    def set_thresholds(self, thresholds: Dict[str, float]) -> None:
        """Живая смена порогов алертов."""
        if isinstance(thresholds, dict):
            self._alert_thresholds = thresholds

    def _recover_from_crash(self) -> None:
        try:
            if os.path.exists(CRASH_DUMP_FILE):
                with open(CRASH_DUMP_FILE, "r") as f:
                    dump = json.load(f)
                dump_time = datetime.fromisoformat(
                    dump.get("timestamp", "2000-01-01"))
                if (datetime.now() - dump_time).total_seconds() < 3600:
                    logger.info("Восстановлены данные после аварийного завершения")
                    self._pending_saves = dump.get("ping_buffer", [])
                    self._flush_saves()
                os.remove(CRASH_DUMP_FILE)
        except Exception:
            pass

    def start(self) -> None:
        self.running = True
        self._stop_event.clear()
        self._ping_thread = threading.Thread(target=self._loop, daemon=True,
                                             name="PingerThread")
        self._ping_thread.start()
        logger.info("Пингер запущен (цель: %s)", self.target)

    def _loop(self) -> None:
        time.sleep(1)
        while self.running and not self._stop_event.is_set():
            try:
                self._do_ping()
                current_time = time.time()
                if (current_time - self._last_save_time > self._save_interval
                        or len(self._pending_saves) >= MAX_BUFFER_SIZE):
                    self._flush_saves()
                    self._last_save_time = current_time

                if self._pending_saves and self._pending_saves[-1].get("timestamp"):
                    last_time = datetime.fromisoformat(
                        self._pending_saves[-1]["timestamp"])
                    if (datetime.now() - last_time).total_seconds() > 60:
                        self._flush_saves()
                        logger.info("Буфер пингов сброшен по таймауту")

                self._stop_event.wait(LOOP_IDLE_SEC)
            except Exception as e:
                logger.error("Ошибка в цикле пингера: %s", e)
                self._stop_event.wait(2)

    def _ping_command(self) -> list:
        if sys.platform == "win32":
            return ["ping", "-n", "1", "-w", "2000", self.target]
        return ["ping", "-c", "1", "-W", "2", self.target]

    def _do_ping(self) -> None:
        process = None
        try:
            with self._process_lock:
                process = subprocess.Popen(
                    self._ping_command(),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW
                    if sys.platform == "win32" else 0)
                self._current_process = process

            try:
                stdout, stderr = process.communicate(timeout=3)
                output = decode_process_output(stdout + stderr)
                ping_ms, is_loss = parse_ping_output(output)
                self._record_result(ping_ms, is_loss)
            except subprocess.TimeoutExpired:
                safe_kill_process(process)
                self._record_loss()
            finally:
                with self._process_lock:
                    self._current_process = None
        except Exception as e:
            logger.error("Ошибка выполнения пинга: %s", e)
            if process:
                safe_kill_process(process)

    def _record_result(self, ping_ms: float, is_loss: bool) -> None:
        with self._data_lock:
            self.total_packets += 1
            if is_loss:
                self.lost_packets += 1
                self.history.append((time.time(), None, True))
            else:
                self.current_ping = ping_ms
                self.last_good_ping = ping_ms
                self.min_ping = min(self.min_ping, ping_ms)
                self.max_ping = max(self.max_ping, ping_ms)
                self.history.append((time.time(), ping_ms, False))

            recent = [m for _, m, lost in list(self.history)[-10:]
                      if not lost and m is not None]
            if len(recent) > 1:
                try:
                    self.jitter = statistics.stdev(recent)
                except Exception:
                    self.jitter = 0.0

            self._pending_saves.append({
                "timestamp": datetime.now().isoformat(),
                "ping_ms": ping_ms if not is_loss else None,
                "loss": 1 if is_loss else 0,
                "jitter": self.jitter,
                "target": self.target,
            })
            self._check_alerts(ping_ms, is_loss)

    def _record_loss(self) -> None:
        with self._data_lock:
            self.total_packets += 1
            self.lost_packets += 1
            self.history.append((time.time(), None, True))
            self._pending_saves.append({
                "timestamp": datetime.now().isoformat(),
                "ping_ms": None,
                "loss": 1,
                "jitter": self.jitter,
                "target": self.target,
            })

    def _check_alerts(self, ping_ms: float, is_loss: bool) -> None:
        """Проверка порогов и генерация алертов (с защитой от спама)."""
        thresholds = self._alert_thresholds
        now = time.time()
        alert = None

        if is_loss:
            loss_percent = self.get_loss_percent()
            if loss_percent > thresholds.get("loss_critical", 5):
                alert = ("КРИТИЧЕСКИЕ ПОТЕРИ", f"Потеря пакетов: {loss_percent:.1f}%")
            elif loss_percent > thresholds.get("loss_high", 2):
                alert = ("ПОТЕРИ ПАКЕТОВ", f"Потеря пакетов: {loss_percent:.1f}%")
        elif ping_ms and ping_ms > thresholds.get("ping_high", 150):
            alert = ("ВЫСОКИЙ ПИНГ", f"Пинг: {ping_ms:.0f}ms")

        if alert is None and self.jitter > thresholds.get("jitter_high", 30):
            alert = ("ВЫСОКИЙ ДЖИТТЕР", f"Джиттер: {self.jitter:.1f}ms")

        if alert:
            alert_type = alert[0]
            # Не чаще одного алерта одного типа в минуту.
            if now - self._last_alert_time.get(alert_type, 0) > 60:
                self._last_alert_time[alert_type] = now
                if self._alert_callback:
                    try:
                        self._alert_callback(alert_type, alert[1])
                    except Exception as e:
                        logger.error("Ошибка alert callback: %s", e)

    def get_display_ping(self) -> float:
        with self._data_lock:
            if self.current_ping is not None and self.current_ping > 0:
                return self.current_ping
            if self.last_good_ping is not None:
                return self.last_good_ping
            return 0

    def get_loss_percent(self) -> float:
        with self._data_lock:
            if self.total_packets == 0:
                return 0.0
            return (self.lost_packets / self.total_packets) * 100

    def get_stats(self) -> Dict[str, Any]:
        with self._data_lock:
            return {
                "history": list(self.history),
                "current": self.current_ping,
                "display": self.get_display_ping(),
                "jitter": self.jitter,
                "loss": self.get_loss_percent(),
                "last_good": self.last_good_ping,
                "min": self.min_ping if self.min_ping != float("inf") else 0,
                "max": self.max_ping,
                "total": self.total_packets,
                "lost": self.lost_packets,
                "buffer_size": len(self._pending_saves),
            }

    def _flush_saves(self) -> None:
        if not self._pending_saves:
            return
        with self._io_lock:
            saves = self._pending_saves.copy()
            self._pending_saves.clear()

        if self._db_callback:
            try:
                self._db_callback(saves)
            except Exception as e:
                logger.error("Ошибка сохранения пингов: %s", e)
                with self._io_lock:
                    self._pending_saves.extend(saves)

    def stop(self) -> None:
        self.running = False
        self._stop_event.set()
        try:
            self._flush_saves()
        except Exception as e:
            logger.error("Ошибка сохранения при остановке: %s", e)
        with self._process_lock:
            if self._current_process:
                safe_kill_process(self._current_process)
                self._current_process = None
        if self._ping_thread and self._ping_thread.is_alive():
            self._ping_thread.join(timeout=3)
        logger.info("Пингер остановлен")
