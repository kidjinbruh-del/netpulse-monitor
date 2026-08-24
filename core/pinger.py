"""
Pinger - ICMP ping с буферизацией
"""

import threading
import time
import subprocess
import sys
import os
import json
import statistics
from collections import deque
from datetime import datetime
import logging

from .utils import safe_kill_process, parse_ping_output, decode_process_output

logger = logging.getLogger(__name__)

class Pinger:
    def __init__(self, target="8.8.8.8", alert_thresholds=None, alert_callback=None):
        self.target = target
        self.running = False
        self._stop_event = threading.Event()
        self._alert_thresholds = alert_thresholds or {}
        self._alert_callback = alert_callback
        self._last_alert_time = {}
        
        self._data_lock = threading.RLock()
        self._io_lock = threading.RLock()
        self._process_lock = threading.Lock()
        self._thread_lock = threading.Lock()
        
        self.history = deque(maxlen=300)
        self.lost_packets = 0
        self.total_packets = 0
        self.current_ping = None
        self.last_good_ping = None
        self.min_ping = float('inf')
        self.max_ping = 0.0
        self.jitter = 0.0
        
        self._pending_saves = []
        self._max_buffer_size = 1000
        self._save_interval = 5
        self._last_save_time = 0
        self._current_process = None
        self._ping_thread = None
        
        self._db_callback = None  # callback для сохранения в БД
        
        self._recover_from_crash()
    
    def set_db_callback(self, callback):
        """Установка callback для сохранения в БД"""
        self._db_callback = callback
    
    def _recover_from_crash(self):
        try:
            if os.path.exists('emergency_ping_dump.json'):
                with open('emergency_ping_dump.json', 'r') as f:
                    dump = json.load(f)
                
                dump_time = datetime.fromisoformat(dump.get('timestamp', '2000-01-01'))
                if (datetime.now() - dump_time).total_seconds() < 3600:
                    logger.info("Восстановлены данные после аварийного завершения")
                    self._pending_saves = dump.get('ping_buffer', [])
                    self._flush_saves()
                os.remove('emergency_ping_dump.json')
        except:
            pass
    
    def start(self):
        self.running = True
        self._stop_event.clear()
        self._ping_thread = threading.Thread(target=self._loop, daemon=True, name="PingerThread")
        self._ping_thread.start()
        logger.info(f"Пингер запущен (цель: {self.target})")
    
    def _loop(self):
        time.sleep(1)
        
        while self.running and not self._stop_event.is_set():
            try:
                self._do_ping()
                
                current_time = time.time()
                if (current_time - self._last_save_time > self._save_interval or
                    len(self._pending_saves) >= self._max_buffer_size):
                    self._flush_saves()
                    self._last_save_time = current_time
                
                if self._pending_saves and self._pending_saves[-1].get('timestamp'):
                    last_time = datetime.fromisoformat(self._pending_saves[-1]['timestamp'])
                    if (datetime.now() - last_time).total_seconds() > 60:
                        self._flush_saves()
                        logger.info("Буфер пингов сброшен по таймауту")
                
                self._stop_event.wait(1)
                
            except Exception as e:
                logger.error(f"Ошибка в цикле пингера: {e}")
                self._stop_event.wait(2)
    
    def _do_ping(self):
        process = None
        try:
            if sys.platform == "win32":
                cmd = ["ping", "-n", "1", "-w", "2000", self.target]
            else:
                cmd = ["ping", "-c", "1", "-W", "2", self.target]
            
            with self._process_lock:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                )
                self._current_process = process
            
            try:
                stdout, stderr = process.communicate(timeout=3)
                output = decode_process_output(stdout + stderr)
                
                ping_ms, is_loss = parse_ping_output(output)
                
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
                    
                    recent_pings = [m for t, m, l in list(self.history)[-10:] 
                                  if not l and m is not None]
                    if len(recent_pings) > 1:
                        try:
                            self.jitter = statistics.stdev(recent_pings)
                        except:
                            self.jitter = 0.0
                    
                    self._pending_saves.append({
                        'timestamp': datetime.now().isoformat(),
                        'ping_ms': ping_ms if not is_loss else None,
                        'loss': 1 if is_loss else 0,
                        'jitter': self.jitter,
                        'target': self.target
                    })
                    
                    self._check_alerts(ping_ms, is_loss)
                    
            except subprocess.TimeoutExpired:
                safe_kill_process(process)
                
                with self._data_lock:
                    self.total_packets += 1
                    self.lost_packets += 1
                    self.history.append((time.time(), None, True))
                    
                    self._pending_saves.append({
                        'timestamp': datetime.now().isoformat(),
                        'ping_ms': None,
                        'loss': 1,
                        'jitter': self.jitter,
                        'target': self.target
                    })
                    
            finally:
                with self._process_lock:
                    self._current_process = None
                    
        except Exception as e:
            logger.error(f"Ошибка выполнения пинга: {e}")
            if process:
                safe_kill_process(process)
    
    def set_alert_callback(self, callback):
        """Установка callback для алертов"""
        self._alert_callback = callback

    def set_target(self, target):
        """Живая смена цели пинга"""
        if target and target != self.target:
            self.target = target
            logger.info(f"Цель пинга изменена на {target}")

    def set_thresholds(self, thresholds):
        """Живая смена порогов алертов"""
        if isinstance(thresholds, dict):
            self._alert_thresholds = thresholds

    def _check_alerts(self, ping_ms, is_loss):
        """Проверка порогов и генерация алертов (с защитой от спама)"""
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
            # Не чаще одного алерта одного типа в минуту
            if now - self._last_alert_time.get(alert_type, 0) > 60:
                self._last_alert_time[alert_type] = now
                if self._alert_callback:
                    try:
                        self._alert_callback(alert_type, alert[1])
                    except Exception as e:
                        logger.error(f"Ошибка alert callback: {e}")
    
    def get_display_ping(self):
        with self._data_lock:
            if self.current_ping is not None and self.current_ping > 0:
                return self.current_ping
            elif self.last_good_ping is not None:
                return self.last_good_ping
            else:
                return 0
    
    def get_loss_percent(self):
        with self._data_lock:
            if self.total_packets == 0:
                return 0.0
            return (self.lost_packets / self.total_packets) * 100
    
    def get_stats(self):
        with self._data_lock:
            return {
                'history': list(self.history),
                'current': self.current_ping,
                'display': self.get_display_ping(),
                'jitter': self.jitter,
                'loss': self.get_loss_percent(),
                'last_good': self.last_good_ping,
                'min': self.min_ping if self.min_ping != float('inf') else 0,
                'max': self.max_ping,
                'total': self.total_packets,
                'lost': self.lost_packets,
                'buffer_size': len(self._pending_saves)
            }
    
    def _flush_saves(self):
        if not self._pending_saves:
            return
        
        with self._io_lock:
            saves = self._pending_saves.copy()
            self._pending_saves.clear()
        
        if self._db_callback:
            try:
                self._db_callback(saves)
            except Exception as e:
                logger.error(f"Ошибка сохранения пингов: {e}")
                with self._io_lock:
                    self._pending_saves.extend(saves)
    
    def stop(self):
        self.running = False
        self._stop_event.set()
        
        try:
            self._flush_saves()
        except Exception as e:
            logger.error(f"Ошибка сохранения при остановке: {e}")
        
        with self._process_lock:
            if self._current_process:
                safe_kill_process(self._current_process)
                self._current_process = None
        
        if self._ping_thread and self._ping_thread.is_alive():
            self._ping_thread.join(timeout=3)
        
        logger.info("Пингер остановлен")