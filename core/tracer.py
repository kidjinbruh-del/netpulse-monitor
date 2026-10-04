"""Tracer — трассировка сети и поиск лучшего DNS.

v3-реализация: тот же контракт Tracer, типизировано.
Исправление legacy: trace() больше не зависит от флага _running
(раньше прямой вызов trace() возвращал пустые хопы); отмена — через stop().
"""
from __future__ import annotations

import logging
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

from .utils import _MS_RE, decode_process_output, parse_trace_output, safe_kill_process

logger = logging.getLogger(__name__)

DEFAULT_SERVERS = {
    "Яндекс DNS": "77.88.8.8",
    "Google DNS": "8.8.8.8",
    "Cloudflare DNS": "1.1.1.1",
    "VK": "87.240.132.67",
    "YouTube": "173.194.222.100",
    "Discord": "162.159.135.234",
}

DEFAULT_DNS_LIST = [
    {"name": "Google", "ip": "8.8.8.8"},
    {"name": "Cloudflare", "ip": "1.1.1.1"},
    {"name": "Яндекс", "ip": "77.88.8.8"},
    {"name": "Quad9", "ip": "9.9.9.9"},
    {"name": "OpenDNS", "ip": "208.67.222.222"},
]

NO_ROUTE = {"name": "Не найден", "ip": "0.0.0.0", "ping": 999.0}
DNS_CACHE_SEC = 60


class Tracer:
    def __init__(self, servers: Optional[Dict[str, str]] = None):
        self.servers = dict(servers or DEFAULT_SERVERS)
        self._running = False
        self._current_process: Optional[subprocess.Popen] = None
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._dns_cache: Dict[str, Dict[str, Any]] = {}

    def trace(
        self, target: str, max_hops: int = 15, timeout: float = 1
    ) -> Dict[str, Any]:
        hops: List[Dict[str, Any]] = []
        total_ms = 0.0
        answered = 0
        self._running = True

        try:
            for ttl in range(1, max_hops + 1):
                if self._stop_event.is_set():
                    break
                hops.append(self._trace_hop(target, ttl, timeout))
                hop = hops[-1]
                if hop["ms"] > 0:
                    total_ms += hop["ms"]
                    answered += 1
                if hop["ip"] == target:
                    break
        finally:
            self._running = False

        return {
            "target": target,
            "hops": hops,
            "avg_ms": total_ms / answered if answered > 0 else 999.0,
            "total_hops": len([h for h in hops if h["ip"] != "*"]),
        }

    def _trace_hop(
        self, target: str, ttl: int, timeout: float
    ) -> Dict[str, Any]:
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-i", str(ttl),
                   "-w", str(int(timeout * 1000)), target]
        else:
            cmd = ["ping", "-c", "1", "-t", str(ttl),
                   "-W", str(int(timeout)), target]
        process = None
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW
                if sys.platform == "win32" else 0)
            with self._lock:
                self._current_process = process
            try:
                stdout, stderr = process.communicate(timeout=timeout + 1)
                output = decode_process_output(stdout + stderr)
                ip, ms = parse_trace_output(output, target=target)
                return {"hop": ttl, "ip": ip, "ms": ms}
            except subprocess.TimeoutExpired:
                safe_kill_process(process)
                return {"hop": ttl, "ip": "*", "ms": 0}
        except Exception as e:
            logger.debug("Ошибка трассировки хопа %s: %s", ttl, e)
            if process:
                safe_kill_process(process)
            return {"hop": ttl, "ip": "*", "ms": 0}
        finally:
            with self._lock:
                if self._current_process == process:
                    self._current_process = None

    def trace_all(
        self, callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        self._running = True
        self._stop_event.clear()
        results = {}
        total = len(self.servers)
        try:
            for i, (name, ip) in enumerate(self.servers.items(), 1):
                if self._stop_event.is_set():
                    break
                try:
                    result = self.trace(ip)
                    results[name] = result
                    if callback:
                        callback(name, result, i / total)
                except Exception as e:
                    logger.error("Ошибка трассировки %s: %s", name, e)
                    if callback:
                        callback(name, {"avg_ms": 999, "total_hops": 0}, i / total)
        finally:
            self._running = False
        return results

    def find_best_dns(
        self,
        progress_callback: Optional[Callable] = None,
        dns_list: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        dns_list = list(dns_list or DEFAULT_DNS_LIST)
        results = []
        total = len(dns_list)
        completed = 0
        with ThreadPoolExecutor(max_workers=min(len(dns_list), 8)) as executor:
            futures = {executor.submit(self._check_dns, s): s for s in dns_list}
            try:
                for future in as_completed(futures, timeout=15):
                    try:
                        result = future.result(timeout=5)
                        results.append(result)
                        completed += 1
                        if progress_callback:
                            progress_callback(completed / total)
                    except Exception as e:
                        logger.error("Ошибка при проверке DNS: %s", e)
                        completed += 1
            except Exception as e:
                logger.error("Проверка DNS прервана: %s", e)

        valid = [r for r in results if r is not None]
        if not valid:
            return dict(NO_ROUTE)
        valid.sort(key=lambda x: x.get("ping", 999))
        best = valid[0]
        if best.get("ping", 999) >= 999:
            return dict(NO_ROUTE)
        return best

    def _check_dns(self, server: Dict[str, str]) -> Dict[str, Any]:
        cache_key = server["ip"]
        cached = self._dns_cache.get(cache_key)
        if cached and time.time() - cached["timestamp"] < DNS_CACHE_SEC:
            return cached["result"]
        if sys.platform == "win32":
            cmd = ["ping", "-n", "3", "-w", "3000", server["ip"]]
        else:
            cmd = ["ping", "-c", "3", "-W", "3", server["ip"]]
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW
                if sys.platform == "win32" else 0)
            try:
                stdout, _ = process.communicate(timeout=10)
                times = _MS_RE.findall(decode_process_output(stdout))
                if times:
                    avg = sum(float(t.replace(",", ".")) for t in times) / len(times)
                    result = {"name": server["name"], "ip": server["ip"],
                              "ping": avg}
                else:
                    result = {"name": server["name"], "ip": server["ip"],
                              "ping": 999.0}
            except subprocess.TimeoutExpired:
                safe_kill_process(process)
                result = {"name": server["name"], "ip": server["ip"],
                          "ping": 999.0}
        except Exception as e:
            logger.error("Ошибка проверки DNS %s: %s", server["name"], e)
            result = {"name": server["name"], "ip": server["ip"], "ping": 999.0}
        self._dns_cache[cache_key] = {"result": result, "timestamp": time.time()}
        return result

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        with self._lock:
            if self._current_process:
                safe_kill_process(self._current_process)
                self._current_process = None
