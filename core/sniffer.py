"""Sniffer — захват и анализ сетевого трафика.

Три режима:
- 'real'   : перехват пакетов через scapy (нужны права администратора) — с данными по IP
- 'psutil' : реальная скорость интерфейсов через psutil (без прав) — без данных по IP

v3-реализация: тот же контракт Sniffer, типизировано.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from .utils import is_admin

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

PRIVATE_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                    "172.29.", "172.30.", "172.31.", "127.")
MAX_IPS = 1000
KEEP_TOP_IPS = 500
COUNTER_RESET_BYTES = 10 ** 12


class Sniffer:
    def __init__(self, mode_config: str = "auto"):
        self.running = False
        self.mode = "psutil"  # real | psutil (определяется в start())
        self._mode_config = mode_config  # auto | psutil
        self.start_time = time.time()
        self.lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread_lock = threading.Lock()

        self.stats: Dict[str, Any] = {
            "bytes_in": 0,
            "bytes_out": 0,
            "packets_in": 0,
            "packets_out": 0,
            "ips": defaultdict(lambda: {"bytes": 0, "packets": 0}),
            "speed_history": deque(maxlen=300),
            "total_mb": 0,
            "max_speed": 0,
        }

        self._last_saved_bytes_in = 0
        self._last_saved_bytes_out = 0
        self._last_db_save = 0.0
        self._last_cleanup = 0.0

        # Для режима psutil: дельты счётчиков интерфейсов.
        self._psutil_last: Optional[Tuple[int, int, float]] = None
        self._updown: Deque[Tuple[float, float, float]] = deque(maxlen=10)

        self._sniff_thread: Optional[threading.Thread] = None
        self._net_thread: Optional[threading.Thread] = None

        self._db_callback: Optional[Callable] = None

    def set_db_callback(self, callback: Callable) -> None:
        """Установка callback для сохранения в БД."""
        self._db_callback = callback

    def start(self) -> None:
        if self.running:
            logger.warning("Сниффер уже запущен")
            return

        self.running = True
        self._stop_event.clear()

        with self._thread_lock:
            self._sniff_thread = None
            self._net_thread = None

        # 1. Полный перехват через scapy (только с правами администратора).
        if self._mode_config in ("auto",) and is_admin():
            if self._try_start_scapy():
                return

        # 2. Реальная скорость интерфейсов через psutil (без прав).
        if self._mode_config in ("auto", "psutil") and PSUTIL_AVAILABLE:
            try:
                psutil.net_io_counters(pernic=True)
                self.mode = "psutil"
                logger.info("Запущен мониторинг трафика через psutil "
                            "(реальные скорости, без per-IP)")
                self._net_thread = threading.Thread(
                    target=self._psutil_loop, daemon=True, name="NetMonThread")
                with self._thread_lock:
                    self._net_thread = self._net_thread
                self._net_thread.start()
                return
            except Exception as e:
                logger.warning("psutil недоступен: %s", e)

        logger.error("Нет доступного режима трафика (real/psutil) — сниффер не запущен")

    def _try_start_scapy(self) -> bool:
        try:
            import socket
            from scapy.all import sniff  # noqa: F401
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                        socket.IPPROTO_IP)
            test_socket.close()
            self.mode = "real"
            logger.info("Запущен реальный сниффинг через scapy")
            thread = threading.Thread(target=self._real_loop, daemon=True)
            with self._thread_lock:
                self._sniff_thread = thread
            thread.start()
            return True
        except Exception as e:
            logger.warning("Scapy не работает: %s", e)
            return False

    def _real_loop(self) -> None:
        from scapy.all import sniff
        while self.running and not self._stop_event.is_set():
            try:
                sniff(
                    prn=self._process_packet,
                    store=False,
                    count=100,
                    timeout=1,
                    stop_filter=lambda x: not self.running
                    or self._stop_event.is_set())
                if self._stop_event.is_set():
                    break
            except Exception as e:
                logger.error("Ошибка сниффера: %s", e)
                if self.running and not self._stop_event.is_set():
                    if self._stop_event.wait(1):
                        break

    def _psutil_loop(self) -> None:
        """Опрос сетевых интерфейсов раз в секунду — реальные дельты up/down."""
        while self.running and not self._stop_event.is_set():
            try:
                counters = psutil.net_io_counters(pernic=True)
                now = time.time()

                sent = sum(c.bytes_sent for name, c in counters.items()
                           if "loopback" not in name.lower())
                recv = sum(c.bytes_recv for name, c in counters.items()
                           if "loopback" not in name.lower())

                if self._psutil_last is not None:
                    last_sent, last_recv, last_t = self._psutil_last
                    d_out = max(0, sent - last_sent)
                    d_in = max(0, recv - last_recv)
                    dt = now - last_t
                    if dt > 0:
                        self._record_traffic(d_in, d_out, now)
                        with self.lock:
                            self._updown.append((now, d_in / dt, d_out / dt))

                self._psutil_last = (sent, recv, now)
            except Exception as e:
                logger.debug("Ошибка опроса интерфейсов: %s", e)

            if self._stop_event.wait(1):
                break

    def _process_packet(self, packet: Any) -> None:
        if not self.running or self._stop_event.is_set():
            return
        try:
            if packet.haslayer("IP"):
                src = packet["IP"].src
                dst = packet["IP"].dst
                size = len(packet)
                src_local = src.startswith(PRIVATE_PREFIXES)
                dst_local = dst.startswith(PRIVATE_PREFIXES)

                if src_local and not dst_local:
                    self._add_packet(dst, size, "out")
                elif dst_local and not src_local:
                    self._add_packet(src, size, "in")
                else:
                    self._add_packet(src, size, "in")
        except Exception as e:
            logger.debug("Ошибка обработки пакета: %s", e)

    def _record_traffic(
        self, in_size: float, out_size: float, current_time: float
    ) -> None:
        """Накопление дельт трафика + периодические сохранение/очистка."""
        with self.lock:
            self.stats["bytes_in"] += in_size
            self.stats["bytes_out"] += out_size
            self.stats["total_mb"] += (in_size + out_size) / 1024 / 1024

            self.stats["speed_history"].append((current_time, in_size + out_size))

            speed_history = self.stats["speed_history"]
            cutoff = current_time - 1
            while speed_history and speed_history[0][0] <= cutoff:
                speed_history.popleft()

            if current_time - self._last_db_save > 5:
                self._save_traffic_to_db()
                self._last_db_save = current_time

            if current_time - self._last_cleanup > 60:
                self._cleanup_old_ips()
                self._last_cleanup = current_time

    def _add_packet(self, ip: str, size: int, direction: str) -> None:
        with self.lock:
            if direction == "in":
                self.stats["packets_in"] += 1
            else:
                self.stats["packets_out"] += 1
            self.stats["ips"][ip]["bytes"] += size
            self.stats["ips"][ip]["packets"] += 1

        self._record_traffic(size if direction == "in" else 0,
                             size if direction != "in" else 0,
                             time.time())

    def _save_traffic_to_db(self) -> None:
        """Сохранение трафика в БД через callback."""
        if self._db_callback:
            try:
                speed = self.get_speed()
                with self.lock:
                    bytes_in_delta = max(
                        0, self.stats["bytes_in"] - self._last_saved_bytes_in)
                    bytes_out_delta = max(
                        0, self.stats["bytes_out"] - self._last_saved_bytes_out)

                    self._last_saved_bytes_in = self.stats["bytes_in"]
                    self._last_saved_bytes_out = self.stats["bytes_out"]

                    if self.stats["bytes_in"] > COUNTER_RESET_BYTES:
                        self.stats["bytes_in"] = 0
                        self._last_saved_bytes_in = 0
                    if self.stats["bytes_out"] > COUNTER_RESET_BYTES:
                        self.stats["bytes_out"] = 0
                        self._last_saved_bytes_out = 0

                    total_in = self.stats["bytes_in"]
                    total_out = self.stats["bytes_out"]

                self._db_callback(speed, total_in, total_out,
                                  bytes_in_delta, bytes_out_delta)
            except Exception as e:
                logger.error("Ошибка сохранения трафика: %s", e)

    def _cleanup_old_ips(self) -> None:
        """Ограничение роста словаря IP (защита от утечки памяти)."""
        with self.lock:
            ips = self.stats["ips"]
            if len(ips) <= MAX_IPS:
                return
            sorted_ips = sorted(ips.items(), key=lambda x: x[1]["bytes"],
                                reverse=True)
            for ip, _ in sorted_ips[KEEP_TOP_IPS:]:
                del ips[ip]

    def get_speed(self) -> float:
        with self.lock:
            current_time = time.time()
            cutoff = current_time - 1
            recent = [size for t, size in self.stats["speed_history"]
                      if t > cutoff]
            speed = sum(recent) / 1024 if recent else 0
            if speed > self.stats["max_speed"]:
                self.stats["max_speed"] = speed
            return speed

    def get_speed_split(self) -> Tuple[float, float]:
        """Раздельные скорости (KB/s): (download, upload)."""
        with self.lock:
            current_time = time.time()
            cutoff = current_time - 3
            recent = [(t, din, dout) for t, din, dout in self._updown
                      if t > cutoff]

        if not recent:
            speed = self.get_speed()
            return (speed * 0.7, speed * 0.3)

        times = [t for t, _, _ in recent]
        t_span = max(times) - min(times)
        if t_span <= 0:
            # Все дельты за один момент времени — просто усредняем.
            n = len(recent)
            return (sum(d for _, d, _ in recent) / n / 1024,
                    sum(d for _, _, d in recent) / n / 1024)
        total_in = sum(d for _, d, _ in recent)
        total_out = sum(d for _, _, d in recent)
        return ((total_in / t_span) / 1024, (total_out / t_span) / 1024)

    def get_uptime(self) -> str:
        seconds = int(time.time() - self.start_time)
        if seconds < 60:
            return f"{seconds}с"
        if seconds < 3600:
            return f"{seconds // 60}м"
        return f"{seconds // 3600}ч {seconds % 3600 // 60}м"

    def get_top_ips(self, limit: int = 6) -> list:
        if self.mode != "real":
            return []
        with self.lock:
            sorted_ips = sorted(
                self.stats["ips"].items(),
                key=lambda x: x[1]["bytes"],
                reverse=True)[:limit]
            return sorted_ips

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "mode": self.mode,
                "speed_history": list(self.stats.get("speed_history", deque())),
                "total_mb": self.stats.get("total_mb", 0),
                "max_speed": self.stats.get("max_speed", 0),
                "bytes_in": self.stats.get("bytes_in", 0),
                "bytes_out": self.stats.get("bytes_out", 0),
                "bytes_in_delta": max(
                    0, self.stats.get("bytes_in", 0) - self._last_saved_bytes_in),
                "bytes_out_delta": max(
                    0, self.stats.get("bytes_out", 0) - self._last_saved_bytes_out),
            }

    def stop(self) -> None:
        self.running = False
        self._stop_event.set()
        try:
            self._save_traffic_to_db()
        except Exception as e:
            logger.error("Ошибка сохранения при остановке: %s", e)
        with self._thread_lock:
            for t in (self._sniff_thread, self._net_thread):
                if t and t.is_alive():
                    t.join(timeout=3)
        logger.info("Сниффер остановлен (режим: %s)", self.mode)
