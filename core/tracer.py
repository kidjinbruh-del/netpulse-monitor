"""
Tracer - трассировка сети и поиск DNS
"""

import threading
import time
import subprocess
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from .utils import safe_kill_process, parse_trace_output, decode_process_output, _MS_RE

logger = logging.getLogger(__name__)

class Tracer:
    def __init__(self):
        self.servers = {
            "Яндекс DNS": "77.88.8.8",
            "Google DNS": "8.8.8.8",
            "Cloudflare DNS": "1.1.1.1",
            "VK": "87.240.132.67",
            "YouTube": "173.194.222.100",
            "Discord": "162.159.135.234",
        }
        self._running = False
        self._current_process = None
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._dns_cache = {}
    
    def trace(self, target, max_hops=15, timeout=1):
        hops = []
        total_ms = 0
        answered = 0
        
        for ttl in range(1, max_hops + 1):
            if not self._running or self._stop_event.is_set():
                break
                
            process = None
            try:
                if sys.platform == "win32":
                    cmd = ["ping", "-n", "1", "-i", str(ttl), "-w", str(timeout * 1000), target]
                else:
                    cmd = ["ping", "-c", "1", "-t", str(ttl), "-W", str(timeout), target]
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                )
                
                with self._lock:
                    self._current_process = process
                
                try:
                    stdout, stderr = process.communicate(timeout=timeout + 1)
                    output = decode_process_output(stdout + stderr)
                    
                    ip, ms = parse_trace_output(output, target=target)
                    if ms > 0:
                        total_ms += ms
                        answered += 1
                    
                    hops.append({"hop": ttl, "ip": ip, "ms": ms})
                    
                    if ip == target:
                        break
                        
                except subprocess.TimeoutExpired:
                    safe_kill_process(process)
                    hops.append({"hop": ttl, "ip": "*", "ms": 0})
                    
            except Exception as e:
                logger.debug(f"Ошибка трассировки хопа {ttl}: {e}")
                if process:
                    safe_kill_process(process)
                hops.append({"hop": ttl, "ip": "*", "ms": 0})
            finally:
                with self._lock:
                    if self._current_process == process:
                        self._current_process = None
        
        avg_ms = total_ms / answered if answered > 0 else 999.0
        total_hops = len([h for h in hops if h["ip"] != "*"])
        
        return {
            "target": target,
            "hops": hops,
            "avg_ms": avg_ms,
            "total_hops": total_hops
        }
    
    def trace_all(self, callback=None):
        self._running = True
        self._stop_event.clear()
        results = {}
        total = len(self.servers)
        
        for i, (name, ip) in enumerate(self.servers.items(), 1):
            if not self._running or self._stop_event.is_set():
                break
                
            try:
                result = self.trace(ip)
                results[name] = result
                
                if callback:
                    callback(name, result, i / total)
                    
            except Exception as e:
                logger.error(f"Ошибка трассировки {name}: {e}")
                if callback:
                    callback(name, {"avg_ms": 999, "total_hops": 0}, i / total)
        
        self._running = False
        return results
    
    def find_best_dns(self, progress_callback=None, dns_list=None):
        if dns_list is None:
            dns_list = [
                {"name": "Google", "ip": "8.8.8.8"},
                {"name": "Cloudflare", "ip": "1.1.1.1"},
                {"name": "Яндекс", "ip": "77.88.8.8"},
                {"name": "Quad9", "ip": "9.9.9.9"},
                {"name": "OpenDNS", "ip": "208.67.222.222"},
            ]
        
        def check_server(server):
            cache_key = server['ip']
            if cache_key in self._dns_cache:
                age = time.time() - self._dns_cache[cache_key]['timestamp']
                if age < 60:
                    return self._dns_cache[cache_key]['result']
            
            try:
                if sys.platform == "win32":
                    cmd = ["ping", "-n", "3", "-w", "3000", server["ip"]]
                else:
                    cmd = ["ping", "-c", "3", "-W", "3", server["ip"]]
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                )
                
                try:
                    stdout, _ = process.communicate(timeout=10)
                    
                    times = _MS_RE.findall(decode_process_output(stdout))
                    if times:
                        avg_ping = sum(float(t.replace(",", ".")) for t in times) / len(times)
                        result = {"name": server["name"], "ip": server["ip"], "ping": avg_ping}
                    else:
                        result = {"name": server["name"], "ip": server["ip"], "ping": 999.0}
                        
                except subprocess.TimeoutExpired:
                    safe_kill_process(process)
                    result = {"name": server["name"], "ip": server["ip"], "ping": 999.0}
                    
            except Exception as e:
                logger.error(f"Ошибка проверки DNS {server['name']}: {e}")
                result = {"name": server["name"], "ip": server["ip"], "ping": 999.0}
            
            self._dns_cache[cache_key] = {
                'result': result,
                'timestamp': time.time()
            }
            
            return result
        
        results = []
        total = len(dns_list)
        completed = 0
        
        with ThreadPoolExecutor(max_workers=min(len(dns_list), 8)) as executor:
            futures = {executor.submit(check_server, s): s for s in dns_list}
            
            for future in as_completed(futures, timeout=15):
                try:
                    result = future.result(timeout=5)
                    results.append(result)
                    
                    completed += 1
                    if progress_callback:
                        progress_callback(completed / total)
                        
                except Exception as e:
                    logger.error(f"Ошибка при проверке DNS: {e}")
                    completed += 1
        
        if not results:
            return {"name": "Не найден", "ip": "0.0.0.0", "ping": 999.0}
        
        valid_results = [r for r in results if r is not None]
        if not valid_results:
            return {"name": "Не найден", "ip": "0.0.0.0", "ping": 999.0}
        
        valid_results.sort(key=lambda x: x.get('ping', 999))
        best = valid_results[0]
        
        if best.get('ping', 999) >= 999:
            return {"name": "Не найден", "ip": "0.0.0.0", "ping": 999.0}
        
        return best
    
    def stop(self):
        self._running = False
        self._stop_event.set()
        
        with self._lock:
            if self._current_process:
                safe_kill_process(self._current_process)
                self._current_process = None