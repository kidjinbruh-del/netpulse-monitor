"""
Network Monitor Pro v7.0 - AI Enterprise Edition
С интеграцией AI агентов и распределенной системой анализа
"""

import customtkinter as ctk
import tkinter as tk
from collections import defaultdict, deque
import threading
import time
import random
import socket
import ctypes
import sys
import os
import subprocess
import statistics
import sqlite3
import re
import json
from datetime import datetime, timedelta
from tkinter import filedialog, messagebox
import logging
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import weakref
import signal
import atexit
from contextlib import contextmanager
import traceback
import asyncio
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ========== НАСТРОЙКА ЛОГГИРОВАНИЯ ==========
class ColoredFormatter(logging.Formatter):
    """Цветное форматирование для логов"""
    
    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
    }
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, '\033[0m')
        reset = '\033[0m'
        message = super().format(record)
        return f"{color}{message}{reset}"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(ColoredFormatter(
    '%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
))
logger.addHandler(console_handler)

file_handler = logging.FileHandler('network_monitor.log', encoding='utf-8')
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
))
logger.addHandler(file_handler)

print("=" * 60)
print("🌐 Network Monitor Pro v7.0 - AI Enterprise Edition")
print("=" * 60)
print(f"🐍 Python: {sys.version.split()[0]}")
print(f"📦 customtkinter: {ctk.__version__}")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

print(f"🔑 Права администратора: {'✅ Да' if is_admin() else '❌ Нет'}")

try:
    import psutil
    PSUTIL_AVAILABLE = True
    print(f"✅ psutil {psutil.__version__} доступен")
except ImportError:
    PSUTIL_AVAILABLE = False
    print("⚠️ psutil не установлен")

# ========== КОНФИГ ==========
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "ping_target": "8.8.8.8",
    "theme": "dark",
    "update_interval": 1000,
    "db_cleanup_days": 30,
    "max_buffer_size": 1000,
    "sniffer_timeout": 1,
    "dns_timeout": 3,
    "ai": {
        "enabled": True,
        "anomaly_threshold": 0.6,
        "training_interval": 300,
        "history_window": 100,
        "features": ["speed", "bytes_in", "bytes_out", "ping_ms", "jitter"],
        "synapse_enabled": True,
        "synapse_hub": "wss://synapse-hub.example.com",
        "agent_name": "network-monitor-pro"
    },
    "alert_thresholds": {
        "ping_high": 150,
        "loss_high": 2,
        "jitter_high": 30,
        "loss_critical": 5
    },
    "targets": {
        "dns": ["8.8.8.8", "1.1.1.1", "77.88.8.8", "9.9.9.9", "208.67.222.222"],
        "services": {
            "Google": "8.8.8.8",
            "Cloudflare": "1.1.1.1",
            "Яндекс": "77.88.8.8",
            "VK": "vk.com",
            "YouTube": "youtube.com"
        }
    },
    "security": {
        "monitor_connections": True,
        "monitor_processes": True,
        "monitor_dns": True,
        "check_autorun": True,
        "check_hosts": True,
        "suspicious_ports": [4444, 1337, 31337, 6667, 4443, 8080, 8888, 3389, 5900, 22, 23]
    }
}

def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                saved_config = json.load(f)
                config = DEFAULT_CONFIG.copy()
                for key, value in saved_config.items():
                    if key in config and isinstance(config[key], dict) and isinstance(value, dict):
                        config[key].update(value)
                    else:
                        config[key] = value
                logger.info(f"Конфигурация загружена из {CONFIG_FILE}")
                return config
    except Exception as e:
        logger.error(f"Ошибка загрузки конфига: {e}")
    
    logger.info("Используется конфигурация по умолчанию")
    return DEFAULT_CONFIG.copy()

config = load_config()

# ========== УТИЛИТЫ ==========
def safe_kill_process(process, timeout=3):
    if not process:
        return
    
    try:
        process.terminate()
        try:
            process.wait(timeout=timeout)
            return
        except subprocess.TimeoutExpired:
            if sys.platform == "win32":
                try:
                    subprocess.run(
                        ['taskkill', '/F', '/T', '/PID', str(process.pid)],
                        capture_output=True,
                        timeout=timeout
                    )
                except:
                    process.kill()
            else:
                process.kill()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    logger.warning(f"Не удалось завершить процесс {process.pid}")
    except Exception as e:
        logger.error(f"Ошибка при завершении процесса: {e}")

def emergency_cleanup():
    try:
        logger.warning("Выполняется аварийное сохранение данных...")
        if 'app' in globals():
            if hasattr(app, 'sniffer'):
                app.sniffer._save_traffic_to_db()
            if hasattr(app, 'pinger'):
                app.pinger._flush_saves()
            if hasattr(app, 'ai_orchestrator'):
                app.ai_orchestrator.stop()
    except Exception as e:
        logger.error(f"Ошибка аварийного сохранения: {e}")

atexit.register(emergency_cleanup)

# ========== ПАРСЕРЫ ==========
def parse_ping_output(output):
    time_match = re.search(r'(?:time|время)[=<]\s*(\d+\.?\d*)', output, re.IGNORECASE)
    if time_match:
        try:
            return float(time_match.group(1)), False
        except ValueError:
            return 0.0, True
    
    if any(x in output for x in ['Превышен интервал ожидания', 'Request timed out', 'TTL expired']):
        return 0.0, True
    
    return 0.0, True

def parse_trace_output(output):
    ip_match = re.search(r'(?:from|ответ от)\s+(\d+\.\d+\.\d+\.\d+)', output, re.IGNORECASE)
    ip = ip_match.group(1) if ip_match else "*"
    time_match = re.search(r'(?:time|время)[=<]\s*(\d+\.?\d*)', output, re.IGNORECASE)
    ms = float(time_match.group(1)) if time_match else 0.0
    return ip, ms

# ========== DATABASE MANAGER ==========
DB = "network_stats.db"

class DatabaseManager:
    ALLOWED_TABLES = {'traffic', 'pings', 'traces', 'alerts', 'security_log', 'ai_predictions'}
    
    def __init__(self, db_path=DB, pool_size=3):
        self.db_path = db_path
        self._pool = queue.Queue(maxsize=pool_size)
        self._lock = threading.RLock()
        self._closed = False
        self._metrics = {'queries': 0, 'errors': 0, 'pool_waits': 0}
        
        for i in range(pool_size):
            try:
                conn = self._create_connection()
                self._pool.put(conn)
                logger.debug(f"Соединение {i+1}/{pool_size} создано")
            except Exception as e:
                logger.error(f"Ошибка создания соединения {i+1}: {e}")
        
        if not self._pool.empty():
            self.init_db()
    
    def _create_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-8000")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.row_factory = sqlite3.Row
        return conn
    
    @contextmanager
    def connection(self):
        if self._closed:
            raise RuntimeError("DatabaseManager закрыт")
        
        conn = None
        start_time = time.time()
        
        try:
            try:
                conn = self._pool.get(timeout=5)
            except queue.Empty:
                logger.warning("Пул соединений пуст, создаем временное")
                conn = self._create_connection()
            
            self._metrics['pool_waits'] += time.time() - start_time
            
            try:
                conn.execute("SELECT 1")
            except sqlite3.Error:
                try:
                    conn.close()
                except:
                    pass
                conn = self._create_connection()
            
            yield conn
            
        except Exception as e:
            logger.error(f"Ошибка получения соединения: {e}")
            raise
            
        finally:
            if conn and not self._closed:
                try:
                    conn.rollback()
                    if self._pool.qsize() < self._pool.maxsize:
                        self._pool.put_nowait(conn)
                    else:
                        conn.close()
                except:
                    try:
                        conn.close()
                    except:
                        pass
    
    def init_db(self):
        try:
            with self.connection() as conn:
                self._migrate_tables(conn)
                
                conn.execute('''CREATE TABLE IF NOT EXISTS traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL, 
                    speed REAL,
                    bytes_in INTEGER, 
                    bytes_out INTEGER,
                    bytes_in_delta INTEGER DEFAULT 0,
                    bytes_out_delta INTEGER DEFAULT 0,
                    anomaly_score REAL DEFAULT 0
                )''')
                
                conn.execute('''CREATE TABLE IF NOT EXISTS pings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL, 
                    ping_ms REAL,
                    loss INTEGER DEFAULT 0,
                    jitter REAL DEFAULT 0,
                    target TEXT DEFAULT '8.8.8.8'
                )''')
                
                conn.execute('''CREATE TABLE IF NOT EXISTS traces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL, 
                    target TEXT,
                    hops INTEGER, 
                    avg_ms REAL
                )''')
                
                conn.execute('''CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL, 
                    alert_type TEXT,
                    message TEXT,
                    acknowledged INTEGER DEFAULT 0,
                    source TEXT DEFAULT 'system'
                )''')
                
                conn.execute('''CREATE TABLE IF NOT EXISTS security_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL, 
                    threat_type TEXT,
                    severity TEXT, 
                    details TEXT,
                    resolved INTEGER DEFAULT 0
                )''')
                
                conn.execute('''CREATE TABLE IF NOT EXISTS ai_predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    metric TEXT,
                    current_value REAL,
                    predicted_value REAL,
                    confidence REAL,
                    trend REAL
                )''')
                
                conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_pings_ts ON pings(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_security_ts ON security_log(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_pings_target ON pings(target)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_predictions_ts ON ai_predictions(timestamp)")
                
                conn.commit()
                logger.info("База данных инициализирована")
                return True
        except Exception as e:
            logger.error(f"Ошибка инициализации БД: {e}")
            return False
    
    def _migrate_tables(self, conn):
        try:
            cursor = conn.execute("PRAGMA table_info(pings)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'jitter' not in columns:
                conn.execute("ALTER TABLE pings ADD COLUMN jitter REAL DEFAULT 0")
            if 'target' not in columns:
                conn.execute("ALTER TABLE pings ADD COLUMN target TEXT DEFAULT '8.8.8.8'")
            
            cursor = conn.execute("PRAGMA table_info(alerts)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'acknowledged' not in columns:
                conn.execute("ALTER TABLE alerts ADD COLUMN acknowledged INTEGER DEFAULT 0")
            if 'source' not in columns:
                conn.execute("ALTER TABLE alerts ADD COLUMN source TEXT DEFAULT 'system'")
            
            cursor = conn.execute("PRAGMA table_info(traffic)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'bytes_in_delta' not in columns:
                conn.execute("ALTER TABLE traffic ADD COLUMN bytes_in_delta INTEGER DEFAULT 0")
            if 'bytes_out_delta' not in columns:
                conn.execute("ALTER TABLE traffic ADD COLUMN bytes_out_delta INTEGER DEFAULT 0")
            if 'anomaly_score' not in columns:
                conn.execute("ALTER TABLE traffic ADD COLUMN anomaly_score REAL DEFAULT 0")
            
            cursor = conn.execute("PRAGMA table_info(security_log)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'resolved' not in columns:
                conn.execute("ALTER TABLE security_log ADD COLUMN resolved INTEGER DEFAULT 0")
            
            conn.commit()
        except Exception as e:
            logger.warning(f"Ошибка миграции таблиц: {e}")
    
    def execute(self, query, params=(), fetch=False, retries=3):
        if self._closed:
            raise RuntimeError("DatabaseManager закрыт")
        
        self._metrics['queries'] += 1
        
        for attempt in range(retries):
            try:
                with self.connection() as conn:
                    cursor = conn.execute(query, params)
                    if fetch:
                        return [dict(row) for row in cursor.fetchall()]
                    else:
                        conn.commit()
                        return cursor.rowcount
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < retries - 1:
                    time.sleep(0.1 * (2 ** attempt))
                    continue
                self._metrics['errors'] += 1
                logger.error(f"SQL ошибка: {e}")
                return None
            except Exception as e:
                self._metrics['errors'] += 1
                logger.error(f"Ошибка выполнения: {e}")
                return None
        
        return None
    
    def execute_many(self, query, params_list, retries=3):
        if self._closed or not params_list:
            return False
        
        for attempt in range(retries):
            try:
                with self.connection() as conn:
                    conn.executemany(query, params_list)
                    conn.commit()
                    return True
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < retries - 1:
                    time.sleep(0.1 * (2 ** attempt))
                    continue
                logger.error(f"Ошибка массового выполнения: {e}")
                return False
            except Exception as e:
                logger.error(f"Ошибка массового выполнения: {e}")
                return False
        
        return False
    
    def cleanup_old_records(self, days=None):
        """Очистка старых записей"""
        if self._closed:
            return False
        
        if days is None:
            days = config.get("db_cleanup_days", 30)
        
        try:
            days = int(days)
            if days < 1:
                days = 30
        except (ValueError, TypeError):
            days = 30
        
        try:
            with self.connection() as conn:
                deleted_total = 0
                for table in self.ALLOWED_TABLES:
                    cursor = conn.execute(
                        f"DELETE FROM {table} WHERE timestamp < datetime('now', ? || ' days')",
                        (f"-{days}",)
                    )
                    deleted_total += cursor.rowcount
                
                if deleted_total > 0:
                    conn.commit()
                    logger.info(f"Очищены записи старше {days} дней (удалено: {deleted_total})")
                    
                    if deleted_total > 1000:
                        try:
                            conn.execute("VACUUM")
                            conn.commit()
                            logger.info("VACUUM выполнен")
                        except sqlite3.OperationalError as e:
                            if "cannot VACUUM" in str(e):
                                logger.warning("VACUUM не выполнен (активна транзакция)")
                            else:
                                raise
                else:
                    logger.info(f"Нет записей для очистки (старше {days} дней)")
                
                return True
                
        except Exception as e:
            logger.error(f"Ошибка очистки БД: {e}")
            return False
    
    def get_metrics(self):
        return {
            **self._metrics,
            'pool_size': self._pool.qsize(),
            'pool_max': self._pool.maxsize
        }
    
    def close(self):
        self._closed = True
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except:
                pass
        logger.info("DatabaseManager закрыт")

db_manager = DatabaseManager(pool_size=3)

# ========== ASYNC WORKER ==========
class AsyncWorker:
    def __init__(self, max_workers=4):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._futures = []
        self._lock = threading.Lock()
        self._shutdown = False
    
    def submit(self, func, args=(), kwargs=None, callback=None, error_callback=None):
        if self._shutdown:
            return None
        
        if kwargs is None:
            kwargs = {}
        
        def wrapped():
            try:
                result = func(*args, **kwargs)
                if callback and not self._shutdown:
                    try:
                        callback(result)
                    except Exception as e:
                        logger.error(f"Ошибка в callback: {e}")
                return result
            except Exception as e:
                logger.error(f"Ошибка в задаче {func.__name__}: {e}", exc_info=True)
                if error_callback and not self._shutdown:
                    try:
                        error_callback(e)
                    except:
                        pass
                elif callback and not self._shutdown:
                    try:
                        callback(None)
                    except:
                        pass
                return None
        
        future = self._executor.submit(wrapped)
        with self._lock:
            self._futures = [f for f in self._futures if not f.done()]
            self._futures.append(future)
        return future
    
    def shutdown(self, wait=False):
        self._shutdown = True
        with self._lock:
            for future in self._futures:
                if not future.done():
                    future.cancel()
            self._futures.clear()
        try:
            self._executor.shutdown(wait=wait)
        except:
            self._executor.shutdown(wait=False)

async_worker = AsyncWorker(max_workers=4)

# ========== AI INTEGRATION ==========
class TrafficAIAgent:
    """AI агент для анализа сетевого трафика"""
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.training_data = []
        self.anomalies = deque(maxlen=100)
        self.is_training = False
        self.last_training_time = 0
        
        self.stats = {
            "total_analyzed": 0,
            "anomalies_detected": 0,
            "avg_confidence": 0.0,
            "model_trained": False
        }
        
        self._lock = threading.RLock()
        
        logger.info("Traffic AI Agent инициализирован")
    
    def train(self, data):
        """Обучение модели на исторических данных"""
        if self.is_training:
            return False
        
        try:
            if len(data) < 10:
                return False
            
            self.is_training = True
            df = pd.DataFrame(data)
            
            features = config.get("ai", {}).get("features", ["speed", "bytes_in", "ping_ms"])
            available_features = [f for f in features if f in df.columns]
            
            if len(available_features) < 2:
                return False
            
            X = df[available_features].fillna(0).values
            X_scaled = self.scaler.fit_transform(X)
            
            self.model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            self.model.fit(X_scaled)
            
            self.last_training_time = time.time()
            self.stats["model_trained"] = True
            
            logger.info(f"Модель обучена на {len(X)} образцах")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка обучения модели: {e}")
            return False
        finally:
            self.is_training = False
    
    def analyze(self, data):
        """Анализ текущих данных на аномалии"""
        with self._lock:
            self.stats["total_analyzed"] += 1
            
            result = {
                "timestamp": datetime.now().isoformat(),
                "is_anomaly": False,
                "confidence": 0.0,
                "score": 0.0,
                "features": {}
            }
            
            if not self.model:
                return result
            
            try:
                features = config.get("ai", {}).get("features", ["speed", "bytes_in", "ping_ms"])
                available_features = [f for f in features if f in data]
                
                if len(available_features) < 2:
                    return result
                
                X = np.array([[data.get(f, 0) for f in available_features]])
                X_scaled = self.scaler.transform(X)
                
                prediction = self.model.predict(X_scaled)
                score = self.model.score_samples(X_scaled)[0]
                
                normalized_score = 1 / (1 + np.exp(-score))
                
                result["score"] = float(normalized_score)
                result["features"] = {f: data.get(f, 0) for f in available_features}
                
                threshold = config.get("ai", {}).get("anomaly_threshold", 0.6)
                if prediction[0] == -1 and normalized_score > threshold:
                    result["is_anomaly"] = True
                    result["confidence"] = normalized_score
                    self.stats["anomalies_detected"] += 1
                    
                    anomaly_record = {
                        "timestamp": datetime.now().isoformat(),
                        "features": result["features"],
                        "confidence": normalized_score,
                        "data": data
                    }
                    self.anomalies.append(anomaly_record)
                    
                    logger.warning(f"Обнаружена аномалия! Уверенность: {normalized_score:.2f}")
                    
                    # Сохраняем в БД
                    db_manager.execute(
                        """INSERT INTO alerts 
                           (timestamp, alert_type, message, source) 
                           VALUES (?,?,?,?)""",
                        (
                            datetime.now().isoformat(),
                            "AI_ANOMALY",
                            f"AI detected anomaly (confidence: {normalized_score:.2f})",
                            "ai_agent"
                        )
                    )
                
                current_avg = self.stats["avg_confidence"] * (self.stats["total_analyzed"] - 1)
                self.stats["avg_confidence"] = (current_avg + normalized_score) / self.stats["total_analyzed"]
                
            except Exception as e:
                logger.error(f"Ошибка анализа: {e}")
            
            return result
    
    def get_anomalies(self, limit=10):
        return list(self.anomalies)[-limit:]
    
    def get_stats(self):
        return self.stats

class PredictiveAgent:
    """AI агент для прогнозирования сетевых проблем"""
    
    def __init__(self):
        self.history = deque(maxlen=1000)
        self.predictions = deque(maxlen=100)
        self._lock = threading.RLock()
        
        logger.info("Predictive AI Agent инициализирован")
    
    def update(self, data):
        with self._lock:
            self.history.append({
                "timestamp": time.time(),
                **data
            })
    
    def predict_next(self, metric="speed", horizon=10):
        with self._lock:
            if len(self.history) < 10:
                return {"error": "Недостаточно данных для прогнозирования"}
            
            try:
                values = [item.get(metric, 0) for item in self.history if metric in item]
                
                if len(values) < 10:
                    return {"error": "Недостаточно данных"}
                
                window = min(10, len(values) // 2)
                recent = values[-window:]
                avg = sum(recent) / len(recent)
                
                if len(values) > window * 2:
                    old_avg = sum(values[-window*2:-window]) / window
                    trend = (avg - old_avg) / old_avg if old_avg > 0 else 0
                else:
                    trend = 0
                
                prediction = {
                    "metric": metric,
                    "current": values[-1] if values else 0,
                    "predicted": avg * (1 + trend * 0.5),
                    "trend": trend,
                    "confidence": 1.0 - (1.0 / (1 + len(values) / 10)),
                    "horizon": horizon,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.predictions.append(prediction)
                
                # Сохраняем в БД
                db_manager.execute(
                    """INSERT INTO ai_predictions 
                       (timestamp, metric, current_value, predicted_value, confidence, trend) 
                       VALUES (?,?,?,?,?,?)""",
                    (
                        datetime.now().isoformat(),
                        metric,
                        prediction["current"],
                        prediction["predicted"],
                        prediction["confidence"],
                        prediction["trend"]
                    )
                )
                
                return prediction
                
            except Exception as e:
                logger.error(f"Ошибка прогнозирования: {e}")
                return {"error": str(e)}
    
    def get_predictions(self):
        return list(self.predictions)

class SynapseAgent:
    """Агент для взаимодействия через Synapse сеть (симуляция)"""
    
    def __init__(self, name, capabilities):
        self.name = name
        self.capabilities = capabilities
        self.connected = False
        self.peers = []
        self.tasks = deque(maxlen=100)
        self._lock = threading.RLock()
        
        logger.info(f"Synapse Agent '{name}' инициализирован")
    
    def connect(self, hub_url):
        with self._lock:
            self.connected = True
            self.peers = ["agent-1", "agent-2", "security-hub"]
            logger.info(f"Synapse Agent '{self.name}' подключен к {hub_url}")
            return True
    
    def broadcast(self, message):
        if not self.connected:
            return False
        
        with self._lock:
            message["from"] = self.name
            message["timestamp"] = datetime.now().isoformat()
            logger.debug(f"Broadcast от {self.name}: {message.get('type', 'unknown')}")
            return True
    
    def delegate_task(self, task, target_agent=None):
        if not self.connected:
            return False
        
        with self._lock:
            task["delegated_from"] = self.name
            task["delegated_to"] = target_agent or "any"
            task["timestamp"] = datetime.now().isoformat()
            self.tasks.append(task)
            logger.info(f"Задача делегирована: {task.get('type', 'unknown')}")
            return True
    
    def get_stats(self):
        with self._lock:
            return {
                "name": self.name,
                "connected": self.connected,
                "peers": len(self.peers),
                "pending_tasks": len(self.tasks),
                "capabilities": self.capabilities
            }

class AIOrchestrator:
    """Оркестратор AI компонентов"""
    
    def __init__(self):
        self.traffic_agent = TrafficAIAgent()
        self.predictive_agent = PredictiveAgent()
        self.synapse_agent = None
        
        self._running = False
        self._training_lock = threading.Lock()
        self._thread = None
        
        logger.info("AI Orchestrator инициализирован")
    
    def initialize_synapse(self):
        if not config.get("ai", {}).get("synapse_enabled", True):
            return None
        
        agent_name = config.get("ai", {}).get("agent_name", "network-monitor-pro")
        capabilities = ["traffic_analysis", "anomaly_detection", "predictive_analysis"]
        
        self.synapse_agent = SynapseAgent(agent_name, capabilities)
        hub_url = config.get("ai", {}).get("synapse_hub", "wss://synapse-hub.example.com")
        self.synapse_agent.connect(hub_url)
        
        return self.synapse_agent
    
    def process_traffic_data(self, data):
        result = {
            "timestamp": datetime.now().isoformat(),
            "analysis": {},
            "prediction": {},
            "stats": {}
        }
        
        if not config.get("ai", {}).get("enabled", True):
            return result
        
        # Обновляем данные для прогнозирования
        self.predictive_agent.update(data)
        
        # Анализ на аномалии
        analysis_result = self.traffic_agent.analyze(data)
        result["analysis"] = analysis_result
        
        # Прогнозирование
        prediction = self.predictive_agent.predict_next("speed")
        result["prediction"] = prediction
        result["stats"] = self.traffic_agent.get_stats()
        
        # Если обнаружена аномалия - рассылаем через Synapse
        if analysis_result.get("is_anomaly", False):
            if self.synapse_agent and self.synapse_agent.connected:
                self.synapse_agent.broadcast({
                    "type": "anomaly_detected",
                    "severity": "high" if analysis_result.get("confidence", 0) > 0.8 else "medium",
                    "data": analysis_result
                })
        
        return result
    
    def train_model(self, historical_data):
        with self._training_lock:
            return self.traffic_agent.train(historical_data)
    
    def start_background_training(self):
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._background_training_loop, daemon=True)
        self._thread.start()
        logger.info("Фоновое обучение AI запущено")
    
    def _background_training_loop(self):
        while self._running:
            try:
                if self.traffic_agent.model:
                    # Получаем свежие данные
                    data = db_manager.execute(
                        """SELECT speed, bytes_in_delta, bytes_out_delta, ping_ms
                        FROM traffic t
                        LEFT JOIN pings p ON datetime(t.timestamp) = datetime(p.timestamp)
                        WHERE t.timestamp > datetime('now','-1 hour')
                        LIMIT 100""",
                        fetch=True
                    )
                    
                    if data and len(data) > 10:
                        historical = [
                            {
                                "speed": row['speed'],
                                "bytes_in": row['bytes_in_delta'],
                                "ping_ms": row.get('ping_ms', 0)
                            }
                            for row in data
                        ]
                        self.traffic_agent.train(historical)
                
                time.sleep(config.get("ai", {}).get("training_interval", 300))
            except Exception as e:
                logger.error(f"Ошибка фонового обучения: {e}")
                time.sleep(60)
    
    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        logger.info("AI Orchestrator остановлен")

ai_orchestrator = AIOrchestrator()

# ========== SNIFFER ==========
class Sniffer:
    def __init__(self):
        self.running = False
        self.real = False
        self.start_time = time.time()
        self.lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread_lock = threading.Lock()
        
        self.stats = {
            "bytes_in": 0, 
            "bytes_out": 0, 
            "packets_in": 0, 
            "packets_out": 0,
            "ips": defaultdict(lambda: {"bytes": 0, "packets": 0}),
            "speed_history": deque(maxlen=300),
            "total_mb": 0,
            "max_speed": 0
        }
        
        self._last_saved_bytes_in = 0
        self._last_saved_bytes_out = 0
        self._last_db_save = 0
        self._last_cleanup = 0
        
        self._sniff_thread = None
        self._sim_thread = None
    
    def start(self):
        if self.running:
            logger.warning("Сниффер уже запущен")
            return
        
        self.running = True
        self._stop_event.clear()
        
        with self._thread_lock:
            self._sniff_thread = None
            self._sim_thread = None
        
        if is_admin():
            try:
                from scapy.all import sniff
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                test_socket.close()
                self.real = True
                logger.info("Запущен реальный сниффинг через scapy")
                self._sniff_thread = threading.Thread(target=self._real_loop, daemon=True)
                self._sniff_thread.start()
                return
            except Exception as e:
                logger.warning(f"Scapy не работает: {e}")
        
        self.real = False
        logger.info("Запущена симуляция трафика")
        self._sim_thread = threading.Thread(target=self._sim_loop, daemon=True)
        self._sim_thread.start()
    
    def _real_loop(self):
        from scapy.all import sniff
        while self.running and not self._stop_event.is_set():
            try:
                sniff(
                    prn=self._process_packet,
                    store=False,
                    count=100,
                    timeout=config.get("sniffer_timeout", 1),
                    stop_filter=lambda x: not self.running or self._stop_event.is_set()
                )
                if self._stop_event.is_set():
                    break
            except Exception as e:
                logger.error(f"Ошибка сниффера: {e}")
                if self.running and not self._stop_event.is_set():
                    if self._stop_event.wait(1):
                        break
    
    def _sim_loop(self):
        while self.running and not self._stop_event.is_set():
            try:
                if self._stop_event.is_set():
                    break
                    
                if random.random() > 0.7:
                    for _ in range(random.randint(3, 10)):
                        if not self.running or self._stop_event.is_set():
                            return
                        ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
                        size = random.randint(500, 1500)
                        direction = "out" if random.random() > 0.3 else "in"
                        self._add_packet(ip, size, direction)
                        if self._stop_event.wait(0.001):
                            return
                else:
                    if not self.running or self._stop_event.is_set():
                        return
                    ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                    size = random.randint(64, 500)
                    direction = "in" if random.random() > 0.4 else "out"
                    self._add_packet(ip, size, direction)
                    time.sleep(0.02)
                    
            except Exception as e:
                logger.debug(f"Ошибка в симуляции: {e}")
                if self._stop_event.wait(0.1):
                    return
    
    def _process_packet(self, packet):
        if not self.running or self._stop_event.is_set():
            return
        
        try:
            if packet.haslayer("IP"):
                src = packet["IP"].src
                size = len(packet)
                is_local = src.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                                          "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."))
                direction = "out" if is_local else "in"
                self._add_packet(src, size, direction)
        except Exception as e:
            logger.debug(f"Ошибка обработки пакета: {e}")
    
    def _add_packet(self, ip, size, direction):
        with self.lock:
            if direction == "in":
                self.stats["bytes_in"] += size
                self.stats["packets_in"] += 1
            else:
                self.stats["bytes_out"] += size
                self.stats["packets_out"] += 1
            
            self.stats["total_mb"] += size / 1024 / 1024
            self.stats["ips"][ip]["bytes"] += size
            self.stats["ips"][ip]["packets"] += 1
            
            current_time = time.time()
            self.stats["speed_history"].append((current_time, size))
            
            cutoff = current_time - 1
            self.stats["speed_history"] = deque(
                [(t, s) for t, s in self.stats["speed_history"] if t > cutoff],
                maxlen=300
            )
            
            if current_time - self._last_db_save > 5:
                self._save_traffic_to_db()
                self._last_db_save = current_time
            
            if current_time - self._last_cleanup > 60:
                self._cleanup_old_ips()
                self._last_cleanup = current_time
    
    def _save_traffic_to_db(self):
        try:
            speed = self.get_speed()
            with self.lock:
                bytes_in_delta = max(0, self.stats["bytes_in"] - self._last_saved_bytes_in)
                bytes_out_delta = max(0, self.stats["bytes_out"] - self._last_saved_bytes_out)
                
                self._last_saved_bytes_in = self.stats["bytes_in"]
                self._last_saved_bytes_out = self.stats["bytes_out"]
                
                if self.stats["bytes_in"] > 10**12:
                    self.stats["bytes_in"] = 0
                    self._last_saved_bytes_in = 0
                if self.stats["bytes_out"] > 10**12:
                    self.stats["bytes_out"] = 0
                    self._last_saved_bytes_out = 0
            
            db_manager.execute(
                """INSERT INTO traffic 
                   (timestamp, speed, bytes_in, bytes_out, bytes_in_delta, bytes_out_delta) 
                   VALUES (?,?,?,?,?,?)""",
                (
                    datetime.now().isoformat(), 
                    speed, 
                    self.stats["bytes_in"], 
                    self.stats["bytes_out"],
                    bytes_in_delta,
                    bytes_out_delta
                )
            )
        except Exception as e:
            logger.error(f"Ошибка сохранения трафика в БД: {e}")
    
    def _cleanup_old_ips(self):
        with self.lock:
            to_remove = [ip for ip, data in self.stats["ips"].items() if data["bytes"] == 0]
            for ip in to_remove:
                del self.stats["ips"][ip]
    
    def get_speed(self):
        with self.lock:
            current_time = time.time()
            cutoff = current_time - 1
            recent = [size for t, size in self.stats["speed_history"] if t > cutoff]
            speed = sum(recent) / 1024 if recent else 0
            
            if speed > self.stats["max_speed"]:
                self.stats["max_speed"] = speed
            
            return speed
    
    def get_uptime(self):
        seconds = int(time.time() - self.start_time)
        if seconds < 60:
            return f"{seconds}с"
        elif seconds < 3600:
            return f"{seconds//60}м"
        else:
            return f"{seconds//3600}ч {seconds%3600//60}м"
    
    def get_top_ips(self, limit=6):
        with self.lock:
            sorted_ips = sorted(
                self.stats["ips"].items(),
                key=lambda x: x[1]["bytes"],
                reverse=True
            )[:limit]
            return sorted_ips
    
    def get_stats(self):
        with self.lock:
            return {
                "speed_history": list(self.stats.get("speed_history", deque())),
                "total_mb": self.stats.get("total_mb", 0),
                "max_speed": self.stats.get("max_speed", 0),
                "bytes_in": self.stats.get("bytes_in", 0),
                "bytes_out": self.stats.get("bytes_out", 0),
                "bytes_in_delta": max(0, self.stats.get("bytes_in", 0) - self._last_saved_bytes_in),
                "bytes_out_delta": max(0, self.stats.get("bytes_out", 0) - self._last_saved_bytes_out)
            }
    
    def stop(self):
        self.running = False
        self._stop_event.set()
        
        try:
            self._save_traffic_to_db()
        except Exception as e:
            logger.error(f"Ошибка сохранения при остановке: {e}")
        
        with self._thread_lock:
            if self._sniff_thread and self._sniff_thread.is_alive():
                self._sniff_thread.join(timeout=3)
            if self._sim_thread and self._sim_thread.is_alive():
                self._sim_thread.join(timeout=3)
        
        logger.info("Сниффер остановлен")

# ========== PINGER ==========
class Pinger:
    def __init__(self, target="8.8.8.8"):
        self.target = target
        self.running = False
        self._stop_event = threading.Event()
        
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
        self._max_buffer_size = config.get("max_buffer_size", 1000)
        self._save_interval = 5
        self._last_save_time = 0
        self._current_process = None
        self._ping_thread = None
        
        self._recover_from_crash()
    
    def _recover_from_crash(self):
        try:
            if os.path.exists('emergency_ping_dump.json'):
                with open('emergency_ping_dump.json', 'r') as f:
                    dump = json.load(f)
                
                dump_time = datetime.fromisoformat(dump.get('timestamp', '2000-01-01'))
                if (datetime.now() - dump_time).seconds < 3600:
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
                    if (datetime.now() - last_time).seconds > 60:
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
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                )
                self._current_process = process
            
            try:
                stdout, stderr = process.communicate(timeout=3)
                output = stdout + stderr
                
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
    
    def _check_alerts(self, ping_ms, is_loss):
        thresholds = config.get("alert_thresholds", {})
        
        if is_loss:
            loss_percent = self.get_loss_percent()
            if loss_percent > thresholds.get("loss_critical", 5):
                self._save_alert("КРИТИЧЕСКИЕ ПОТЕРИ", f"Потеря пакетов: {loss_percent:.1f}%")
        elif ping_ms and ping_ms > thresholds.get("ping_high", 150):
            self._save_alert("ВЫСОКИЙ ПИНГ", f"Пинг: {ping_ms:.0f}ms")
        
        if self.jitter > thresholds.get("jitter_high", 30):
            self._save_alert("ВЫСОКИЙ ДЖИТТЕР", f"Джиттер: {self.jitter:.1f}ms")
    
    def _save_alert(self, alert_type, message):
        try:
            db_manager.execute(
                """INSERT INTO alerts 
                   (timestamp, alert_type, message, source) 
                   VALUES (?,?,?,?)""",
                (datetime.now().isoformat(), alert_type, message, "pinger")
            )
        except Exception as e:
            logger.error(f"Ошибка сохранения алерта: {e}")
    
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
        
        try:
            success = db_manager.execute_many(
                """INSERT INTO pings 
                   (timestamp, ping_ms, loss, jitter, target) 
                   VALUES (?,?,?,?,?)""",
                [(s['timestamp'], s['ping_ms'], s['loss'], s['jitter'], s['target']) 
                 for s in saves]
            )
            
            if not success:
                logger.warning(f"Не удалось сохранить {len(saves)} пингов")
                with self._io_lock:
                    self._pending_saves.extend(saves)
                    
        except Exception as e:
            logger.error(f"Ошибка сохранения пингов: {e}")
            try:
                with open('emergency_ping_dump.json', 'w') as f:
                    json.dump({
                        'timestamp': datetime.now().isoformat(),
                        'ping_buffer': saves
                    }, f)
            except:
                pass
    
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

# ========== TRACER ==========
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
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                )
                
                with self._lock:
                    self._current_process = process
                
                try:
                    stdout, stderr = process.communicate(timeout=timeout + 1)
                    output = stdout + stderr
                    
                    ip, ms = parse_trace_output(output)
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
                
                db_manager.execute(
                    """INSERT INTO traces 
                       (timestamp, target, hops, avg_ms) 
                       VALUES (?,?,?,?)""",
                    (datetime.now().isoformat(), ip, result["total_hops"], result["avg_ms"])
                )
                
                if callback:
                    callback(name, result, i / total)
                    
            except Exception as e:
                logger.error(f"Ошибка трассировки {name}: {e}")
                if callback:
                    callback(name, {"avg_ms": 999, "total_hops": 0}, i / total)
        
        self._running = False
        return results
    
    def find_best_dns(self, progress_callback=None):
        dns_servers = []
        
        for dns in config.get("targets", {}).get("dns", []):
            if not any(d['ip'] == dns for d in dns_servers):
                dns_servers.append({"name": f"DNS_{dns}", "ip": dns})
        
        standard_dns = [
            {"name": "Google", "ip": "8.8.8.8"},
            {"name": "Cloudflare", "ip": "1.1.1.1"},
            {"name": "Яндекс", "ip": "77.88.8.8"},
            {"name": "Quad9", "ip": "9.9.9.9"},
            {"name": "OpenDNS", "ip": "208.67.222.222"},
        ]
        
        for dns in standard_dns:
            if not any(d['ip'] == dns['ip'] for d in dns_servers):
                dns_servers.append(dns)
        
        def check_server(server):
            cache_key = server['ip']
            if cache_key in self._dns_cache:
                age = time.time() - self._dns_cache[cache_key]['timestamp']
                if age < 60:
                    return self._dns_cache[cache_key]['result']
            
            try:
                if sys.platform == "win32":
                    cmd = ["ping", "-n", "3", "-w", str(config.get("dns_timeout", 3) * 1000), server["ip"]]
                else:
                    cmd = ["ping", "-c", "3", "-W", str(config.get("dns_timeout", 3)), server["ip"]]
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                )
                
                try:
                    stdout, _ = process.communicate(timeout=10)
                    
                    times = re.findall(r'time[=<]\s*(\d+\.?\d*)', stdout, re.IGNORECASE)
                    if times:
                        avg_ping = sum(float(t) for t in times) / len(times)
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
        total = len(dns_servers)
        completed = 0
        
        with ThreadPoolExecutor(max_workers=min(len(dns_servers), 8)) as executor:
            futures = {executor.submit(check_server, s): s for s in dns_servers}
            
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

# ========== SECURITY SCANNER ==========
class SecurityScanner:
    WHITELIST_PROCESSES = {
        'chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe', 'opera.exe',
        'svchost.exe', 'explorer.exe', 'winlogon.exe', 'services.exe',
        'python.exe', 'python3.exe', 'pycharm.exe', 'code.exe',
        'Code.exe', 'CodeSetup*.exe', 'CodeSetup*.tmp',
        'vscode*.exe', 'vscode*.tmp',
        'docker.exe', 'docker-desktop.exe',
        'msbuild.exe', 'devenv.exe'
    }
    
    WHITELIST_PATHS = {
        'windows', 'program files', 'microsoft', 'visual studio', 
        'jetbrains', 'intellij', 'android studio',
        'vscode-stable-user-x64', 'is-'
    }
    
    LEGITIMATE_IPS = {'127.0.0.1', '0.0.0.0', '::1'}
    LEGITIMATE_DOMAINS = {'localhost', 'localhost.localdomain'}
    
    @staticmethod
    def detect_suspicious_connections():
        suspicious = []
        suspicious_ports = config.get("security", {}).get("suspicious_ports", [4444, 1337, 8080])
        
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                result = subprocess.run(
                    ["netstat", "-tunp"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            
            for line in result.stdout.split('\n'):
                if ':' in line and '.' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            if sys.platform == "win32":
                                remote = parts[2]
                                pid = parts[-1]
                            else:
                                if len(parts) >= 7:
                                    remote = parts[4]
                                    pid = parts[6].split('/')[0]
                                else:
                                    continue
                            
                            remote_port = remote.rsplit(':', 1)[-1] if ':' in remote else ''
                            if remote_port and remote_port.isdigit():
                                port = int(remote_port)
                                if port in suspicious_ports:
                                    proc_name = f"PID:{pid}"
                                    if PSUTIL_AVAILABLE:
                                        try:
                                            proc_name = psutil.Process(int(pid)).name()
                                        except:
                                            pass
                                    
                                    suspicious.append({
                                        "process": proc_name,
                                        "pid": pid,
                                        "remote": remote,
                                        "reason": f"Подозрительный порт {port}",
                                        "severity": "HIGH"
                                    })
                        except (ValueError, IndexError):
                            continue
        except subprocess.TimeoutExpired:
            logger.warning("Таймаут при сканировании соединений")
        except Exception as e:
            logger.error(f"Ошибка сканирования соединений: {e}")
        
        return suspicious
    
    @staticmethod
    def detect_hidden_processes():
        if not PSUTIL_AVAILABLE:
            return []
        
        hidden = []
        if sys.platform == "win32":
            suspicious_paths = ['temp', 'appdata\\local\\temp', 'downloads', 'cache']
        else:
            suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/', '/run/user/', '.cache']
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name'] or 'unknown'
                    exe_path = proc.info['exe'] or ''
                    
                    is_whitelisted = (
                        any(p in name.lower() for p in [p.lower() for p in SecurityScanner.WHITELIST_PROCESSES if '*' not in p]) or
                        any(wp in exe_path.lower() for wp in SecurityScanner.WHITELIST_PATHS)
                    )
                    
                    if is_whitelisted:
                        continue
                    
                    if any(path in exe_path.lower() for path in suspicious_paths):
                        connections = 0
                        try:
                            if hasattr(proc, 'net_connections'):
                                net_conns = proc.net_connections()
                            elif hasattr(proc, 'connections'):
                                net_conns = proc.connections()
                            else:
                                net_conns = []
                            connections = len(net_conns)
                        except:
                            pass
                        
                        hidden.append({
                            "process": name,
                            "pid": pid,
                            "reason": "Запущен из подозрительной директории",
                            "connections": connections,
                            "path": exe_path,
                            "severity": "MEDIUM" if connections == 0 else "HIGH"
                        })
                        
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                except Exception as e:
                    logger.debug(f"Ошибка проверки процесса: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Ошибка сканирования процессов: {e}")
        
        return hidden
    
    @staticmethod
    def check_hosts_file():
        suspicious = []
        
        if sys.platform == "win32":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        else:
            hosts_path = "/etc/hosts"
        
        if not os.path.exists(hosts_path):
            logger.debug(f"Файл hosts не найден: {hosts_path}")
            return suspicious
        
        if not os.access(hosts_path, os.R_OK):
            logger.warning(f"Нет прав на чтение файла hosts: {hosts_path}")
            return suspicious
        
        known_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'vk.com', 'yandex.ru',
            'microsoft.com', 'apple.com', 'steam.com', 'discord.com', 'telegram.org',
            'github.com', 'twitter.com', 'instagram.com', 'whatsapp.com'
        ]
        
        try:
            with open(hosts_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    
                    ip = parts[0]
                    if ip in SecurityScanner.LEGITIMATE_IPS:
                        continue
                    
                    domains_text = ' '.join(parts[1:]).lower()
                    found_domains = set()
                    
                    for domain in known_domains:
                        if re.search(r'\b' + re.escape(domain) + r'\b', domains_text):
                            found_domains.add(domain)
                    
                    for domain in found_domains:
                        if domain in SecurityScanner.LEGITIMATE_DOMAINS:
                            continue
                        
                        suspicious.append({
                            "domain": domains_text,
                            "redirects_to": ip,
                            "reason": f"Перенаправление {domain}",
                            "severity": "CRITICAL",
                            "line": line_num
                        })
        except Exception as e:
            logger.error(f"Ошибка проверки hosts: {e}")
        
        return suspicious
    
    @staticmethod
    def check_autorun():
        suspicious = []
        
        try:
            if sys.platform == "win32":
                reg_paths = [
                    r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                    r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
                ]
                
                for reg_path in reg_paths:
                    result = subprocess.run(
                        ["reg", "query", reg_path],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    
                    for line in result.stdout.split('\n'):
                        if 'REG_SZ' in line or 'REG_EXPAND_SZ' in line:
                            suspicious_paths = ['temp', 'appdata\\local\\temp', 'downloads']
                            if any(path in line.lower() for path in suspicious_paths):
                                suspicious.append({
                                    "entry": line.strip()[:100],
                                    "reason": "Подозрительная автозагрузка",
                                    "severity": "MEDIUM"
                                })
            else:
                try:
                    result = subprocess.run(
                        ["crontab", "-l"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if any(path in line for path in ['/tmp/', '/var/tmp/', '.cache']):
                                suspicious.append({
                                    "entry": line[:100],
                                    "reason": "Подозрительная запись в crontab",
                                    "severity": "HIGH"
                                })
                except:
                    pass
                
                autostart_dirs = [
                    os.path.expanduser("~/.config/autostart"),
                    "/etc/xdg/autostart"
                ]
                for dir_path in autostart_dirs:
                    if os.path.exists(dir_path):
                        for file in os.listdir(dir_path):
                            if file.endswith('.desktop'):
                                try:
                                    with open(os.path.join(dir_path, file), 'r', encoding='utf-8') as f:
                                        content = f.read()
                                        if 'Exec=' in content:
                                            suspicious.append({
                                                "entry": f"{file} в {dir_path}",
                                                "reason": "Автозагрузка",
                                                "severity": "MEDIUM"
                                            })
                                except:
                                    pass
        except Exception as e:
            logger.error(f"Ошибка проверки автозагрузки: {e}")
        
        return suspicious
    
    @staticmethod
    def run_full_scan():
        logger.info("Запуск сканирования безопасности...")
        
        results = {
            "Подозрительные соединения": SecurityScanner.detect_suspicious_connections(),
            "Скрытые процессы": SecurityScanner.detect_hidden_processes(),
            "HOSTS файл": SecurityScanner.check_hosts_file(),
            "Автозагрузка": SecurityScanner.check_autorun()
        }
        
        total_threats = sum(len(v) for v in results.values())
        logger.info(f"Сканирование завершено. Найдено угроз: {total_threats}")
        return results

# ========== GRACEFUL SHUTDOWN ==========
class GracefulShutdown:
    def __init__(self, app):
        self.app = app
        self.max_shutdown_time = 10
        self.shutdown_start = None
        self.steps_completed = []
    
    def execute(self):
        self.shutdown_start = time.time()
        logger.info("Начинаем graceful shutdown...")
        
        shutdown_steps = [
            ("Остановка UI обновлений", self._stop_ui_updates),
            ("Остановка AI оркестратора", self._stop_ai),
            ("Остановка сниффера", self._stop_sniffer),
            ("Остановка пингера", self._stop_pinger),
            ("Сохранение буферов", self._flush_all_buffers),
            ("Закрытие окон", self._close_windows),
            ("Остановка воркеров", self._stop_workers),
            ("Закрытие БД", self._close_database),
        ]
        
        for step_name, step_func in shutdown_steps:
            if self._check_timeout(step_name):
                break
            
            try:
                step_func()
                self.steps_completed.append(step_name)
                logger.info(f"✓ {step_name}")
            except Exception as e:
                logger.error(f"✗ Ошибка на шаге '{step_name}': {e}")
            
            time.sleep(0.1)
        
        if not self._check_timeout("завершение"):
            elapsed = time.time() - self.shutdown_start
            logger.info(f"Graceful shutdown завершен за {elapsed:.1f}с")
            self._clean_exit(0)
        else:
            self._force_exit()
    
    def _check_timeout(self, step_name):
        elapsed = time.time() - self.shutdown_start
        if elapsed > self.max_shutdown_time:
            logger.critical(f"Таймаут превышен на шаге: {step_name} ({elapsed:.1f}с)")
            return True
        
        if elapsed > self.max_shutdown_time * 0.8:
            logger.warning(f"Приближаемся к таймауту на шаге: {step_name} ({elapsed:.1f}с)")
        
        return False
    
    def _stop_ui_updates(self):
        self.app.running = False
        if hasattr(self.app, '_update_timer'):
            try:
                self.app.root.after_cancel(self.app._update_timer)
            except:
                pass
    
    def _stop_ai(self):
        if hasattr(self.app, 'ai_orchestrator'):
            try:
                self.app.ai_orchestrator.stop()
            except:
                pass
    
    def _stop_sniffer(self):
        if hasattr(self.app, 'sniffer'):
            self.app.sniffer.stop()
    
    def _stop_pinger(self):
        if hasattr(self.app, 'pinger'):
            self.app.pinger.stop()
    
    def _flush_all_buffers(self):
        if hasattr(self.app, 'sniffer'):
            try:
                self.app.sniffer._save_traffic_to_db()
            except:
                pass
        if hasattr(self.app, 'pinger'):
            try:
                self.app.pinger._flush_saves()
            except:
                pass
    
    def _close_windows(self):
        if hasattr(self.app, 'trace_window') and self.app.trace_window:
            try:
                if hasattr(self.app.trace_window, 'tracer'):
                    self.app.trace_window.tracer.stop()
                self.app.trace_window.destroy()
            except:
                pass
        
        if hasattr(self.app, 'security_window') and self.app.security_window:
            try:
                self.app.security_window.destroy()
            except:
                pass
        
        if hasattr(self.app, 'ai_dashboard') and self.app.ai_dashboard:
            try:
                self.app.ai_dashboard.destroy()
            except:
                pass
        
        try:
            self.app.root.quit()
            self.app.root.destroy()
        except:
            pass
    
    def _stop_workers(self):
        try:
            async_worker.shutdown(wait=False)
        except:
            pass
    
    def _close_database(self):
        try:
            db_manager.close()
        except:
            pass
    
    def _force_exit(self):
        logger.critical("Принудительное завершение процесса")
        try:
            self._flush_all_buffers()
        except:
            pass
        os._exit(1)
    
    def _clean_exit(self, code=0):
        sys.exit(code)

# ========== MINI CHART ==========
class MiniChart:
    def __init__(self, parent, width=500, height=130, color="#9146FF"):
        self.canvas = tk.Canvas(
            parent,
            width=width,
            height=height,
            bg="#0e0e16",
            highlightthickness=0
        )
        self.canvas.pack(fill="x", padx=12, pady=(0, 8))
        self.color = color
        self.width = width
        self.height = height
        self._last_draw_hash = None
    
    def draw(self, data):
        if len(data) < 2:
            return
        
        try:
            data_tuple = tuple(data)
            data_hash = hash(data_tuple)
            if data_hash == self._last_draw_hash:
                return
            self._last_draw_hash = data_hash
        except:
            return
        
        try:
            self.canvas.delete("all")
            
            w = self.canvas.winfo_width() or self.width
            h = self.canvas.winfo_height() or self.height
            
            for i in range(1, 5):
                y = h * i // 5
                self.canvas.create_line(0, y, w, y, fill="#1e1e28", dash=(2, 4))
            
            valid_data = [(t, v) for t, v in data if v is not None and v > 0]
            if not valid_data:
                return
            
            values = [v for _, v in valid_data]
            max_val = max(values) or 1
            
            points = []
            step = max(1, len(valid_data) // min(w, 200))
            
            for i in range(0, len(valid_data), step):
                chunk = valid_data[i:i + step]
                if not chunk:
                    continue
                
                avg_val = sum(v for _, v in chunk) / len(chunk)
                x = i * w / len(valid_data)
                y = h - (avg_val / max_val * h * 0.85)
                points.extend([x, y])
            
            if len(points) >= 4:
                self.canvas.create_line(points, fill=self.color, width=2, smooth=True)
                
                if len(points) >= 2:
                    last_x, last_y = points[-2], points[-1]
                    self.canvas.create_oval(
                        last_x-3, last_y-3,
                        last_x+3, last_y+3,
                        fill=self.color,
                        outline=""
                    )
        except:
            pass
    
    def clear(self):
        self.canvas.delete("all")
        self._last_draw_hash = None

# ========== AI DASHBOARD ==========
class AIDashboard:
    def __init__(self, parent, orchestrator):
        self.win = ctk.CTkToplevel(parent)
        self.win.title("🤖 AI Control Center")
        self.win.geometry("800x700")
        self.win.configure(fg_color="#0b0b10")
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        
        self.ai = orchestrator
        self.is_running = True
        self._build_ui()
        self._start_update_loop()
    
    def _on_close(self):
        self.is_running = False
        self.win.destroy()
    
    def _build_ui(self):
        header = ctk.CTkFrame(self.win, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(
            header,
            text="🤖 AI CONTROL CENTER",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#9146FF"
        ).pack(side="left")
        
        status_frame = ctk.CTkFrame(self.win, fg_color="#12121a", corner_radius=10)
        status_frame.pack(fill="x", padx=15, pady=5)
        
        self.synapse_status = ctk.CTkLabel(
            status_frame,
            text="🔌 Synapse: Подключение...",
            font=ctk.CTkFont(size=12),
            text_color="#f1c40f"
        )
        self.synapse_status.pack(pady=5)
        
        stats_frame = ctk.CTkFrame(self.win, fg_color="#12121a", corner_radius=10)
        stats_frame.pack(fill="x", padx=15, pady=5)
        
        stats_grid = ctk.CTkFrame(stats_frame, fg_color="transparent")
        stats_grid.pack(fill="x", padx=10, pady=10)
        
        self.ai_stats_labels = {}
        stats_items = [
            ("total_analyzed", "📊 Всего анализов"),
            ("anomalies_detected", "🚨 Аномалий"),
            ("avg_confidence", "📈 Средняя уверенность"),
            ("model_trained", "🧠 Модель обучена")
        ]
        
        for i, (key, label) in enumerate(stats_items):
            frame = ctk.CTkFrame(stats_grid, fg_color="transparent")
            frame.grid(row=i//2, column=i%2, padx=10, pady=5, sticky="ew")
            
            ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=11), text_color="#6a6a7a").pack(anchor="w")
            
            self.ai_stats_labels[key] = ctk.CTkLabel(
                frame,
                text="...",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color="#e0e0e0"
            )
            self.ai_stats_labels[key].pack(anchor="w")
        
        anomalies_frame = ctk.CTkFrame(self.win, fg_color="#12121a", corner_radius=10)
        anomalies_frame.pack(fill="both", expand=True, padx=15, pady=5)
        
        ctk.CTkLabel(
            anomalies_frame,
            text="🚨 ПОСЛЕДНИЕ АНОМАЛИИ",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#ff4757"
        ).pack(anchor="w", padx=12, pady=8)
        
        self.anomalies_list = ctk.CTkScrollableFrame(anomalies_frame, fg_color="transparent")
        self.anomalies_list.pack(fill="both", expand=True, padx=12, pady=8)
        
        predictions_frame = ctk.CTkFrame(self.win, fg_color="#12121a", corner_radius=10)
        predictions_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(
            predictions_frame,
            text="🔮 ПРОГНОЗЫ",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#f1c40f"
        ).pack(anchor="w", padx=12, pady=8)
        
        self.predictions_list = ctk.CTkFrame(predictions_frame, fg_color="transparent")
        self.predictions_list.pack(fill="x", padx=12, pady=8)
        
        btn_frame = ctk.CTkFrame(self.win, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkButton(
            btn_frame,
            text="🧠 Переобучить модель",
            command=self._retrain_model,
            fg_color="#9146FF",
            hover_color="#7b3fc0",
            height=35
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            btn_frame,
            text="🔄 Обновить",
            command=self._refresh,
            fg_color="#1e1e28",
            text_color="#e0e0e0",
            height=35
        ).pack(side="left", padx=5)
    
    def _start_update_loop(self):
        if not self.is_running:
            return
        
        self._update_ui()
        self.win.after(2000, self._start_update_loop)
    
    def _update_ui(self):
        try:
            if self.ai.synapse_agent:
                synapse_stats = self.ai.synapse_agent.get_stats()
                if synapse_stats.get('connected'):
                    self.synapse_status.configure(
                        text=f"🔌 Synapse: Подключен ({synapse_stats.get('peers', 0)} пиров)",
                        text_color="#2ed573"
                    )
                else:
                    self.synapse_status.configure(
                        text="🔌 Synapse: Отключен",
                        text_color="#ff4757"
                    )
            
            stats = self.ai.traffic_agent.get_stats()
            for key, label in self.ai_stats_labels.items():
                if key == "model_trained":
                    value = "✅ Да" if stats.get(key) else "❌ Нет"
                    color = "#2ed573" if stats.get(key) else "#ff4757"
                elif key == "avg_confidence":
                    value = f"{stats.get(key, 0):.2f}"
                    color = "#f1c40f"
                else:
                    value = str(stats.get(key, 0))
                    color = "#e0e0e0"
                
                label.configure(text=value, text_color=color)
            
            self._update_anomalies()
            self._update_predictions()
            
        except Exception as e:
            logger.error(f"Ошибка обновления AI Dashboard: {e}")
    
    def _update_anomalies(self):
        for widget in self.anomalies_list.winfo_children():
            widget.destroy()
        
        anomalies = self.ai.traffic_agent.get_anomalies(10)
        
        if not anomalies:
            ctk.CTkLabel(
                self.anomalies_list,
                text="✅ Аномалий не обнаружено",
                font=ctk.CTkFont(size=12),
                text_color="#2ed573"
            ).pack(pady=10)
            return
        
        for anomaly in anomalies:
            frame = ctk.CTkFrame(self.anomalies_list, fg_color="#1a1a2a", corner_radius=8)
            frame.pack(fill="x", pady=3)
            
            time_label = ctk.CTkLabel(
                frame,
                text=anomaly.get('timestamp', '')[:19],
                font=ctk.CTkFont(size=10),
                text_color="#6a6a7a"
            )
            time_label.pack(anchor="w", padx=10, pady=(5, 0))
            
            features = anomaly.get('features', {})
            confidence = anomaly.get('confidence', 0)
            severity = "🔴" if confidence > 0.8 else "🟡"
            
            details = [
                f"Скорость: {features.get('speed', 0):.1f} KB/s",
                f"Пинг: {features.get('ping_ms', 0):.0f}ms",
                f"Уверенность: {confidence:.2f}"
            ]
            
            ctk.CTkLabel(
                frame,
                text=f"{severity} {' | '.join(details)}",
                font=ctk.CTkFont(size=11),
                text_color="#e0e0e0"
            ).pack(anchor="w", padx=10, pady=(0, 5))
    
    def _update_predictions(self):
        for widget in self.predictions_list.winfo_children():
            widget.destroy()
        
        predictions = self.ai.predictive_agent.get_predictions()
        
        if not predictions:
            ctk.CTkLabel(
                self.predictions_list,
                text="⏳ Нет прогнозов",
                font=ctk.CTkFont(size=12),
                text_color="#6a6a7a"
            ).pack(pady=5)
            return
        
        last = predictions[-1]
        if 'error' not in last:
            frame = ctk.CTkFrame(self.predictions_list, fg_color="transparent")
            frame.pack(fill="x")
            
            metric = last.get('metric', 'speed')
            current = last.get('current', 0)
            predicted = last.get('predicted', 0)
            trend = last.get('trend', 0) * 100
            
            trend_symbol = "⬆️" if trend > 0 else "⬇️" if trend < 0 else "➡️"
            trend_color = "#2ed573" if trend > 0 else "#ff4757" if trend < 0 else "#f1c40f"
            
            ctk.CTkLabel(
                frame,
                text=f"{trend_symbol} {metric.upper()}: {current:.1f} → {predicted:.1f} (тренд: {trend:+.1f}%)",
                font=ctk.CTkFont(size=12),
                text_color=trend_color
            ).pack(side="left")
    
    def _retrain_model(self):
        try:
            data = db_manager.execute(
                """SELECT speed, bytes_in_delta, bytes_out_delta, ping_ms
                FROM traffic t
                LEFT JOIN pings p ON date(t.timestamp) = date(p.timestamp)
                ORDER BY t.timestamp DESC 
                LIMIT 1000""",
                fetch=True
            )
            
            if data:
                historical = [
                    {
                        "speed": row['speed'],
                        "bytes_in": row['bytes_in_delta'],
                        "ping_ms": row.get('ping_ms', 0)
                    }
                    for row in data
                ]
                
                success = self.ai.traffic_agent.train(historical)
                if success:
                    messagebox.showinfo("Успех", "Модель успешно переобучена!")
                else:
                    messagebox.showwarning("Предупреждение", "Не удалось переобучить модель")
        except Exception as e:
            logger.error(f"Ошибка переобучения: {e}")
            messagebox.showerror("Ошибка", f"Ошибка переобучения: {e}")
    
    def _refresh(self):
        self._update_ui()
    
    def destroy(self):
        self.is_running = False
        if self.win:
            self.win.destroy()

# ========== TRACE WINDOW ==========
class TraceWindow:
    def __init__(self, parent):
        self.win = ctk.CTkToplevel(parent)
        self.win.title("🌍 Трассировка")
        self.win.geometry("650x600")
        self.win.configure(fg_color="#0b0b10")
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        
        self.tracer = Tracer()
        self.results_frame = None
        self.progress = None
        self.status_lbl = None
        self.is_running = False
        
        self._build_ui()
        self.win.after(500, self.run_trace)
    
    def _safe_update(self, func):
        try:
            if hasattr(self, 'win') and self.win and self.win.winfo_exists():
                func()
        except:
            pass
    
    def _on_close(self):
        self.is_running = False
        if hasattr(self, 'tracer'):
            self.tracer.stop()
        if self.win:
            self.win.destroy()
    
    def _build_ui(self):
        header = ctk.CTkFrame(self.win, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(
            header,
            text="🌍 ТРАССИРОВКА СЕТИ",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#9146FF"
        ).pack(side="left")
        
        btn_frame = ctk.CTkFrame(self.win, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkButton(btn_frame, text="🚀 Трассировать все", command=self.run_trace, fg_color="#9146FF", height=30).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🔍 Лучший DNS", command=self.find_dns, fg_color="#f1c40f", text_color="#000", height=30).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🏥 Проверка сервисов", command=self.check_health, fg_color="#2ed573", text_color="#000", height=30).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🔄 Обновить", command=self.refresh, fg_color="#1e1e28", text_color="#e0e0e0", height=30).pack(side="left", padx=5)
        
        self.progress = ctk.CTkProgressBar(self.win, fg_color="#1e1e28", progress_color="#9146FF", height=6)
        self.progress.pack(fill="x", padx=15, pady=5)
        self.progress.set(0)
        
        self.status_lbl = ctk.CTkLabel(self.win, text="Готов к работе", font=ctk.CTkFont(size=12), text_color="#6a6a7a")
        self.status_lbl.pack(pady=5)
        
        self.results_frame = ctk.CTkScrollableFrame(self.win, fg_color="transparent")
        self.results_frame.pack(fill="both", expand=True, padx=15, pady=10)
    
    def refresh(self):
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        self.run_trace()
    
    def run_trace(self):
        if self.is_running:
            return
        
        self.is_running = True
        self.progress.set(0)
        self._safe_update(lambda: self.status_lbl.configure(text="⏳ Трассировка..."))
        
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        threading.Thread(target=self._trace_thread, daemon=True).start()
    
    def _trace_thread(self):
        try:
            def callback(name, result, progress):
                self._safe_update(lambda: self._update_progress(name, result, progress))
            
            results = self.tracer.trace_all(callback)
            self._safe_update(lambda: self._show_results(results))
        except Exception as e:
            logger.error(f"Ошибка трассировки: {e}")
            self._safe_update(lambda: self.status_lbl.configure(text=f"❌ Ошибка: {e}", text_color="#ff4757"))
        finally:
            self.is_running = False
    
    def _update_progress(self, name, result, progress):
        self.progress.set(progress)
        avg_ms = result.get('avg_ms', 999)
        total_hops = result.get('total_hops', 0)
        self.status_lbl.configure(text=f"⏳ {name}: {avg_ms:.0f}ms ({total_hops} хопов)")
    
    def find_dns(self):
        if self.is_running:
            return
        
        self.is_running = True
        self._safe_update(lambda: self.status_lbl.configure(text="🔍 Поиск лучшего DNS..."))
        
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        threading.Thread(target=self._dns_thread, daemon=True).start()
    
    def _dns_thread(self):
        try:
            def progress_callback(value):
                self._safe_update(lambda: self.progress.set(value))
            
            best = self.tracer.find_best_dns(progress_callback)
            self._safe_update(lambda: self._show_dns_result(best))
        except Exception as e:
            logger.error(f"Ошибка поиска DNS: {e}")
            self._safe_update(lambda: self.status_lbl.configure(text=f"❌ Ошибка: {e}", text_color="#ff4757"))
        finally:
            self.is_running = False
    
    def check_health(self):
        if self.is_running:
            return
        
        self.is_running = True
        self._safe_update(lambda: self.status_lbl.configure(text="🏥 Проверка сервисов..."))
        
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        threading.Thread(target=self._health_thread, daemon=True).start()
    
    def _health_thread(self):
        try:
            services = config.get("targets", {}).get("services", {"Google": "8.8.8.8"})
            health = {}
            
            for name, host in services.items():
                try:
                    start = time.time()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((host, 443))
                    latency = (time.time() - start) * 1000
                    sock.close()
                    health[name] = {"status": "✅", "latency_ms": round(latency, 1)}
                except:
                    health[name] = {"status": "❌", "latency_ms": None}
            
            self._safe_update(lambda: self._show_health(health))
        except Exception as e:
            logger.error(f"Ошибка проверки здоровья: {e}")
            self._safe_update(lambda: self.status_lbl.configure(text=f"❌ Ошибка: {e}", text_color="#ff4757"))
        finally:
            self.is_running = False
    
    def _show_dns_result(self, best):
        self.status_lbl.configure(text="✅ Готово", text_color="#2ed573")
        self.progress.set(1.0)
        
        card = ctk.CTkFrame(self.results_frame, fg_color="#12121a", corner_radius=12, border_width=1, border_color="#1e1e28")
        card.pack(fill="x", pady=10)
        
        ctk.CTkLabel(card, text="🏆 ЛУЧШИЙ DNS", font=ctk.CTkFont(size=14, weight="bold"), text_color="#f1c40f").pack(pady=10)
        
        if best and best.get('ping', 999) < 999:
            ctk.CTkLabel(card, text=f"{best['name']} ({best['ip']})", font=ctk.CTkFont(size=20, weight="bold"), text_color="#2ed573").pack()
            ctk.CTkLabel(card, text=f"Пинг: {best['ping']:.0f}ms", font=ctk.CTkFont(size=16), text_color="#e0e0e0").pack(pady=5)
        else:
            ctk.CTkLabel(card, text="❌ Не удалось найти доступный DNS", font=ctk.CTkFont(size=16), text_color="#ff4757").pack(pady=10)
    
    def _show_health(self, health):
        self.status_lbl.configure(text="✅ Проверка завершена", text_color="#2ed573")
        self.progress.set(1.0)
        
        for name, data in health.items():
            color = "#2ed573" if "✅" in data["status"] else "#ff4757"
            
            card = ctk.CTkFrame(self.results_frame, fg_color="#12121a", corner_radius=10, border_width=1, border_color="#1e1e28")
            card.pack(fill="x", pady=3)
            
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=8)
            
            ctk.CTkLabel(row, text=name, font=ctk.CTkFont(size=13, weight="bold"), text_color="#e0e0e0").pack(side="left")
            text = f"{data['status']} {data['latency_ms']:.0f}ms" if data['latency_ms'] else data['status']
            ctk.CTkLabel(row, text=text, font=ctk.CTkFont(size=13), text_color=color).pack(side="right")
    
    def _show_results(self, results):
        self.status_lbl.configure(text="✅ Трассировка завершена", text_color="#2ed573")
        self.progress.set(1.0)
        
        for name, data in results.items():
            avg_ms = data.get('avg_ms', 999)
            
            if avg_ms < 50:
                color = "#2ed573"
                status = "Отлично"
            elif avg_ms < 150:
                color = "#f1c40f"
                status = "Средне"
            else:
                color = "#ff4757"
                status = "Плохо"
            
            card = ctk.CTkFrame(self.results_frame, fg_color="#12121a", corner_radius=10, border_width=1, border_color="#1e1e28")
            card.pack(fill="x", pady=3)
            
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=8)
            
            ctk.CTkLabel(row, text=name, font=ctk.CTkFont(size=13, weight="bold"), text_color="#e0e0e0").pack(side="left")
            ctk.CTkLabel(row, text=f"{avg_ms:.0f}ms - {status}", font=ctk.CTkFont(size=13, weight="bold"), text_color=color).pack(side="right")
            
            bar = ctk.CTkProgressBar(card, fg_color="#1e1e28", progress_color=color, height=4)
            bar.pack(fill="x", padx=12, pady=(0, 5))
            bar.set(min(avg_ms / 300, 1.0))
            
            ctk.CTkLabel(card, text=f"Хопов: {data.get('total_hops', 0)} | IP: {data.get('target', 'Unknown')}", 
                       font=ctk.CTkFont(size=10), text_color="#6a6a7a").pack(anchor="w", padx=12, pady=(0, 8))

# ========== SECURITY WINDOW ==========
class SecurityWindow:
    def __init__(self, parent):
        self.win = ctk.CTkToplevel(parent)
        self.win.title("🛡️ Безопасность")
        self.win.geometry("700x650")
        self.win.configure(fg_color="#0b0b10")
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        
        self.results_frame = None
        self.status_lbl = None
        self.threat_count = None
        self.is_running = False
        
        self._build_ui()
        self.win.after(500, self.run_scan)
    
    def _safe_update(self, func):
        try:
            if self.win and self.win.winfo_exists():
                func()
        except:
            pass
    
    def _on_close(self):
        self.is_running = False
        if self.win:
            self.win.destroy()
    
    def _build_ui(self):
        header = ctk.CTkFrame(self.win, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(header, text="🛡️ СКАНЕР БЕЗОПАСНОСТИ", font=ctk.CTkFont(size=18, weight="bold"), text_color="#ff4757").pack(side="left")
        
        btn_frame = ctk.CTkFrame(self.win, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkButton(btn_frame, text="🔍 Полное сканирование", command=self.run_scan, fg_color="#ff4757", hover_color="#ee5a24", height=35).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🔄 Быстрая проверка", command=self.quick_scan, fg_color="#f1c40f", text_color="#000", height=35).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="📄 Экспорт отчёта", command=self.export_report, fg_color="#2ed573", text_color="#000", height=35).pack(side="right", padx=5)
        ctk.CTkButton(btn_frame, text="🔄 Обновить", command=self.refresh, fg_color="#1e1e28", text_color="#e0e0e0", height=35).pack(side="right", padx=5)
        
        self.status_frame = ctk.CTkFrame(self.win, fg_color="#12121a", corner_radius=10, border_width=1, border_color="#1e1e28")
        self.status_frame.pack(fill="x", padx=15, pady=5)
        
        self.status_lbl = ctk.CTkLabel(self.status_frame, text="Готов к сканированию", font=ctk.CTkFont(size=14, weight="bold"), text_color="#e0e0e0")
        self.status_lbl.pack(pady=10)
        
        self.threat_count = ctk.CTkLabel(self.status_frame, text="", font=ctk.CTkFont(size=24, weight="bold"), text_color="#2ed573")
        self.threat_count.pack(pady=(0, 10))
        
        self.results_frame = ctk.CTkScrollableFrame(self.win, fg_color="transparent")
        self.results_frame.pack(fill="both", expand=True, padx=15, pady=10)
        
        info = ctk.CTkFrame(self.win, fg_color="#12121a", corner_radius=8)
        info.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(info, text="💡 Запускайте сканирование регулярно для выявления угроз", font=ctk.CTkFont(size=10), text_color="#6a6a7a").pack(pady=5)
    
    def refresh(self):
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        self.run_scan()
    
    def run_scan(self):
        if self.is_running:
            return
        
        self.is_running = True
        self._safe_update(lambda: self.status_lbl.configure(text="⏳ Полное сканирование...", text_color="#f1c40f"))
        self._safe_update(lambda: self.threat_count.configure(text=""))
        
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        threading.Thread(target=self._full_scan_thread, daemon=True).start()
    
    def quick_scan(self):
        if self.is_running:
            return
        
        self.is_running = True
        self._safe_update(lambda: self.status_lbl.configure(text="⏳ Быстрая проверка...", text_color="#f1c40f"))
        self._safe_update(lambda: self.threat_count.configure(text=""))
        
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        threading.Thread(target=self._quick_scan_thread, daemon=True).start()
    
    def _full_scan_thread(self):
        try:
            results = SecurityScanner.run_full_scan()
            self._safe_update(lambda: self._show_results(results, "полное"))
        except Exception as e:
            logger.error(f"Ошибка сканирования: {e}")
            self._safe_update(lambda: self.status_lbl.configure(text=f"❌ Ошибка: {e}", text_color="#ff4757"))
        finally:
            self.is_running = False
    
    def _quick_scan_thread(self):
        try:
            results = {
                "Подозрительные соединения": SecurityScanner.detect_suspicious_connections(),
                "HOSTS файл": SecurityScanner.check_hosts_file(),
            }
            self._safe_update(lambda: self._show_results(results, "быстрая"))
        except Exception as e:
            logger.error(f"Ошибка быстрой проверки: {e}")
            self._safe_update(lambda: self.status_lbl.configure(text=f"❌ Ошибка: {e}", text_color="#ff4757"))
        finally:
            self.is_running = False
    
    def _show_results(self, results, scan_type):
        total_threats = sum(len(v) for v in results.values())
        
        if total_threats == 0:
            self.status_lbl.configure(text="✅ Угроз не обнаружено", text_color="#2ed573")
            self.threat_count.configure(text="🛡️ Чисто", text_color="#2ed573")
        elif total_threats < 3:
            self.status_lbl.configure(text=f"⚠️ Подозрений: {total_threats}", text_color="#f1c40f")
            self.threat_count.configure(text=f"{total_threats} 🔶", text_color="#f1c40f")
        else:
            self.status_lbl.configure(text=f"🚨 УГРОЗ: {total_threats}", text_color="#ff4757")
            self.threat_count.configure(text=f"{total_threats} 🔴", text_color="#ff4757")
        
        for category, threats in results.items():
            if not threats:
                continue
            
            cat_frame = ctk.CTkFrame(self.results_frame, fg_color="transparent")
            cat_frame.pack(fill="x", pady=(10, 5))
            
            ctk.CTkLabel(cat_frame, text=f"📋 {category} ({len(threats)})", font=ctk.CTkFont(size=14, weight="bold"), text_color="#9146FF").pack(anchor="w")
            
            for threat in threats:
                severity = threat.get("severity", "LOW")
                
                if severity == "CRITICAL":
                    color = "#ff4757"
                    icon = "🔴"
                elif severity == "HIGH":
                    color = "#ff6b6b"
                    icon = "🟠"
                elif severity == "MEDIUM":
                    color = "#f1c40f"
                    icon = "🟡"
                else:
                    color = "#2ed573"
                    icon = "🟢"
                
                card = ctk.CTkFrame(self.results_frame, fg_color="#12121a", corner_radius=8, border_width=1, border_color="#1e1e28")
                card.pack(fill="x", pady=2)
                
                line1 = ctk.CTkFrame(card, fg_color="transparent")
                line1.pack(fill="x", padx=10, pady=(8, 2))
                
                process = threat.get("process", threat.get("domain", threat.get("entry", "Неизвестно")))
                ctk.CTkLabel(line1, text=f"{icon} {process}", font=ctk.CTkFont(size=12, weight="bold"), text_color="#e0e0e0").pack(side="left")
                ctk.CTkLabel(line1, text=severity, font=ctk.CTkFont(size=10), text_color=color).pack(side="right")
                
                line2 = ctk.CTkFrame(card, fg_color="transparent")
                line2.pack(fill="x", padx=10, pady=(0, 8))
                
                reason = threat.get("reason", "")
                extra = ""
                if "remote" in threat:
                    extra = f" → {threat['remote']}"
                if "redirects_to" in threat:
                    extra = f" → {threat['redirects_to']}"
                if "connections" in threat:
                    extra = f" ({threat['connections']} соед.)"
                if "line" in threat:
                    extra = f" (строка {threat['line']})"
                
                ctk.CTkLabel(line2, text=f"{reason}{extra}", font=ctk.CTkFont(size=10), text_color="#6a6a7a").pack(side="left")
    
    def export_report(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Текстовый файл", "*.txt")])
        if not path:
            return
        
        try:
            results = SecurityScanner.run_full_scan()
            
            with open(path, "w", encoding="utf-8") as f:
                f.write("=" * 60 + "\n")
                f.write("ОТЧЁТ БЕЗОПАСНОСТИ\n")
                f.write(f"Сгенерирован: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")
                
                total = sum(len(v) for v in results.values())
                f.write(f"Всего угроз: {total}\n\n")
                
                for category, threats in results.items():
                    if threats:
                        f.write(f"{'='*40}\n")
                        f.write(f"{category} ({len(threats)})\n")
                        f.write(f"{'='*40}\n")
                        
                        for t in threats:
                            f.write(f"  [{t.get('severity', 'LOW')}] {t.get('reason', '')}\n")
                            if 'process' in t:
                                f.write(f"    Процесс: {t['process']}\n")
                            if 'pid' in t:
                                f.write(f"    PID: {t['pid']}\n")
                            if 'remote' in t:
                                f.write(f"    Удалённый: {t['remote']}\n")
                            if 'path' in t:
                                f.write(f"    Путь: {t['path']}\n")
                            f.write("\n")
            
            messagebox.showinfo("Успех", f"Отчёт сохранён: {os.path.basename(path)}")
        except Exception as e:
            logger.error(f"Ошибка экспорта отчета: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить отчёт: {e}")

# ========== MAIN APPLICATION ==========
class App:
    def __init__(self):
        logger.info("Запуск приложения...")
        
        if hasattr(db_manager, 'cleanup_old_records'):
            async_worker.submit(db_manager.cleanup_old_records)
        else:
            logger.warning("Метод cleanup_old_records не найден, пропускаем очистку")
        
        self.sniffer = Sniffer()
        self.pinger = Pinger(config["ping_target"])
        self.running = True
        self._update_timer = None
        
        self.trace_window = None
        self.security_window = None
        self.ai_dashboard = None
        self._is_closing = False
        self._close_lock = threading.Lock()
        
        # Инициализация AI
        self.ai_orchestrator = ai_orchestrator
        if config.get("ai", {}).get("enabled", True):
            self.ai_orchestrator.initialize_synapse()
            self.ai_orchestrator.start_background_training()
            
            # Обучение на исторических данных
            self._collect_historical_data()
        
        ctk.set_appearance_mode(config.get("theme", "dark"))
        ctk.set_default_color_theme("blue")
        
        self.root = ctk.CTk()
        self.root.title("Network Monitor Pro v7.0 - AI Enterprise")
        self.root.geometry("580x950")
        self.root.minsize(500, 800)
        self.root.configure(fg_color="#0b0b10")
        
        self.root.update_idletasks()
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - 580) // 2
        y = (screen_height - 950) // 2
        self.root.geometry(f"+{x}+{y}")
        
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        
        signal.signal(signal.SIGINT, lambda s, f: self._on_close(s, f))
        signal.signal(signal.SIGTERM, lambda s, f: self._on_close(s, f))
        
        self._build_ui()
        
        self.root.after(500, self._start_monitoring)
        self._start_update_loop()
        
        logger.info("Приложение запущено")
    
    def _collect_historical_data(self):
        try:
            data = db_manager.execute(
                """SELECT speed, bytes_in_delta, bytes_out_delta, ping_ms
                FROM traffic t
                LEFT JOIN pings p ON date(t.timestamp) = date(p.timestamp)
                ORDER BY t.timestamp DESC 
                LIMIT 1000""",
                fetch=True
            )
            
            if data and len(data) > 10:
                historical = [
                    {
                        "speed": row['speed'],
                        "bytes_in": row['bytes_in_delta'],
                        "ping_ms": row.get('ping_ms', 0)
                    }
                    for row in data
                ]
                self.ai_orchestrator.traffic_agent.train(historical)
                logger.info("AI модель обучена на исторических данных")
        except Exception as e:
            logger.error(f"Ошибка сбора исторических данных: {e}")
    
    def _safe_update(self, func):
        try:
            if self.root and self.root.winfo_exists():
                func()
        except:
            pass
    
    def _on_close(self, signum=None, frame=None):
        with self._close_lock:
            if self._is_closing:
                return
            self._is_closing = True
        
        logger.info(f"Получен сигнал закрытия: {signum if signum else 'window'}")
        
        shutdown = GracefulShutdown(self)
        shutdown.execute()
    
    def _build_ui(self):
        header = ctk.CTkFrame(self.root, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(10, 5))
        
        ctk.CTkLabel(header, text="🌐 NETWORK MONITOR PRO v7.0", font=ctk.CTkFont(size=18, weight="bold"), text_color="#9146FF").pack(side="left")
        
        self.uptime_label = ctk.CTkLabel(header, text="0с", font=ctk.CTkFont(size=12), text_color="#6a6a7a")
        self.uptime_label.pack(side="right", padx=5)
        
        mode_text = "🔴 Live" if is_admin() else "⚡ Sim"
        self.mode_label = ctk.CTkLabel(header, text=mode_text, font=ctk.CTkFont(size=12), text_color="#2ed573" if is_admin() else "#f1c40f")
        self.mode_label.pack(side="right", padx=10)
        
        btn_row = ctk.CTkFrame(self.root, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=3)
        
        ctk.CTkButton(btn_row, text="🤖 AI", command=self._open_ai_dashboard, fg_color="#12121a", border_width=1, border_color="#9146FF", text_color="#9146FF", height=30).pack(side="left", padx=3)
        ctk.CTkButton(btn_row, text="🌍 Трассировка", command=self._open_trace, fg_color="#12121a", border_width=1, border_color="#9146FF", text_color="#9146FF", height=30).pack(side="left", padx=3)
        ctk.CTkButton(btn_row, text="🛡️ Безопасность", command=self._open_security, fg_color="#12121a", border_width=1, border_color="#ff4757", text_color="#ff4757", height=30).pack(side="left", padx=3)
        ctk.CTkButton(btn_row, text="📄 Отчёт", command=self._export_report, fg_color="#12121a", border_width=1, border_color="#2ed573", text_color="#2ed573", height=30).pack(side="left", padx=3)
        
        containers = ctk.CTkFrame(self.root, fg_color="transparent")
        containers.pack(fill="x", padx=15, pady=5)
        
        speed_container = ctk.CTkFrame(containers, fg_color="#12121a", corner_radius=12, border_width=1, border_color="#1e1e28")
        speed_container.pack(side="left", fill="both", expand=True, padx=(0, 4))
        
        self.speed_label = ctk.CTkLabel(speed_container, text="0.0", font=ctk.CTkFont(size=34, weight="bold"), text_color="#2ed573")
        self.speed_label.pack(pady=(12, 0))
        
        ctk.CTkLabel(speed_container, text="скорость KB/s", font=ctk.CTkFont(size=10), text_color="#6a6a7a").pack()
        
        speed_row = ctk.CTkFrame(speed_container, fg_color="transparent")
        speed_row.pack(fill="x", padx=12, pady=8)
        
        self.max_speed_label = ctk.CTkLabel(speed_row, text="пик 0", font=ctk.CTkFont(size=10), text_color="#f1c40f")
        self.max_speed_label.pack(side="left")
        
        self.total_label = ctk.CTkLabel(speed_row, text="0 MB", font=ctk.CTkFont(size=10), text_color="#6a6a7a")
        self.total_label.pack(side="right")
        
        ping_container = ctk.CTkFrame(containers, fg_color="#12121a", corner_radius=12, border_width=1, border_color="#1e1e28")
        ping_container.pack(side="right", fill="both", expand=True, padx=(4, 0))
        
        self.ping_label = ctk.CTkLabel(ping_container, text="0", font=ctk.CTkFont(size=34, weight="bold"), text_color="#2ed573")
        self.ping_label.pack(pady=(12, 0))
        
        ctk.CTkLabel(ping_container, text="пинг ms", font=ctk.CTkFont(size=10), text_color="#6a6a7a").pack()
        
        ping_row = ctk.CTkFrame(ping_container, fg_color="transparent")
        ping_row.pack(fill="x", padx=12, pady=8)
        
        self.jitter_label = ctk.CTkLabel(ping_row, text="джиттер 0", font=ctk.CTkFont(size=10), text_color="#f1c40f")
        self.jitter_label.pack(side="left")
        
        self.loss_label = ctk.CTkLabel(ping_row, text="потери 0%", font=ctk.CTkFont(size=10), text_color="#ff4757")
        self.loss_label.pack(side="right")
        
        status_container = ctk.CTkFrame(self.root, fg_color="#12121a", corner_radius=10, border_width=1, border_color="#1e1e28")
        status_container.pack(fill="x", padx=15, pady=6)
        
        self.alert_label = ctk.CTkLabel(status_container, text="⏳ Запуск...", font=ctk.CTkFont(size=12, weight="bold"), text_color="#f1c40f")
        self.alert_label.pack(pady=8)
        
        speed_chart_container = ctk.CTkFrame(self.root, fg_color="#12121a", corner_radius=12, border_width=1, border_color="#1e1e28")
        speed_chart_container.pack(fill="x", padx=15, pady=4)
        
        ctk.CTkLabel(speed_chart_container, text="📈 СКОРОСТЬ", font=ctk.CTkFont(size=11, weight="bold"), text_color="#9146FF").pack(anchor="w", padx=12, pady=(8, 2))
        self.speed_chart = MiniChart(speed_chart_container, width=500, height=130, color="#9146FF")
        
        ping_chart_container = ctk.CTkFrame(self.root, fg_color="#12121a", corner_radius=12, border_width=1, border_color="#1e1e28")
        ping_chart_container.pack(fill="x", padx=15, pady=4)
        
        ctk.CTkLabel(ping_chart_container, text="📉 ПИНГ", font=ctk.CTkFont(size=11, weight="bold"), text_color="#9146FF").pack(anchor="w", padx=12, pady=(8, 2))
        self.ping_chart = MiniChart(ping_chart_container, width=500, height=110, color="#2ed573")
        
        ip_container = ctk.CTkFrame(self.root, fg_color="#12121a", corner_radius=12, border_width=1, border_color="#1e1e28")
        ip_container.pack(fill="both", expand=True, padx=15, pady=4)
        
        ctk.CTkLabel(ip_container, text="🌍 ПОДКЛЮЧЕНИЯ", font=ctk.CTkFont(size=11, weight="bold"), text_color="#9146FF").pack(anchor="w", padx=12, pady=(8, 3))
        
        self.ip_list = ctk.CTkScrollableFrame(ip_container, fg_color="transparent")
        self.ip_list.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        
        status_bar = ctk.CTkFrame(self.root, fg_color="#0d0d0d", height=26, corner_radius=0)
        status_bar.pack(fill="x", side="bottom")
        
        self.status_dot = ctk.CTkFrame(status_bar, width=8, height=8, corner_radius=4, fg_color="#f1c40f")
        self.status_dot.place(x=12, y=9)
        
        ctk.CTkLabel(status_bar, text="Live", font=ctk.CTkFont(size=10), text_color="#6a6a7a").place(x=24, y=4)
        
        self.avg_label = ctk.CTkLabel(status_bar, text="", font=ctk.CTkFont(size=10), text_color="#6a6a7a")
        self.avg_label.pack(side="right", padx=12)
        
        # AI статус
        ai_status = ctk.CTkLabel(status_bar, text="🤖 AI: Активен", font=ctk.CTkFont(size=10), text_color="#9146FF")
        ai_status.place(x=100, y=4)
    
    def _start_monitoring(self):
        try:
            self.sniffer.start()
            self.pinger.start()
            
            self._safe_update(lambda: self.alert_label.configure(text="✅ Сеть стабильна", text_color="#2ed573"))
            self._safe_update(lambda: self.status_dot.configure(fg_color="#2ed573"))
            
            logger.info("Мониторинг запущен")
        except Exception as e:
            logger.error(f"Ошибка запуска мониторинга: {e}")
            self._safe_update(lambda: self.alert_label.configure(text="❌ Ошибка мониторинга", text_color="#ff4757"))
    
    def _start_update_loop(self):
        if not self.running:
            return
        
        self._update_ui()
        self._update_timer = self.root.after(config.get("update_interval", 1000), self._start_update_loop)
    
    def _update_ui(self):
        if not self.running:
            return
        
        try:
            sniffer_stats = self.sniffer.get_stats()
            pinger_stats = self.pinger.get_stats()
            speed = self.sniffer.get_speed()
            
            speed_color = "#2ed573" if speed < 500 else "#f1c40f" if speed < 1000 else "#ff4757"
            self._safe_update(lambda: self.speed_label.configure(text=f"{speed:.1f}", text_color=speed_color))
            self._safe_update(lambda: self.max_speed_label.configure(text=f"пик {sniffer_stats['max_speed']:.0f}"))
            self._safe_update(lambda: self.total_label.configure(text=f"{sniffer_stats['total_mb']:.1f} MB"))
            
            display_ping = pinger_stats.get('display', 0)
            ping_color = "#2ed573" if display_ping < 50 else "#f1c40f" if display_ping < 150 else "#ff4757"
            self._safe_update(lambda: self.ping_label.configure(text=f"{display_ping:.0f}", text_color=ping_color))
            self._safe_update(lambda: self.jitter_label.configure(text=f"джиттер {pinger_stats['jitter']:.0f}ms"))
            self._safe_update(lambda: self.loss_label.configure(text=f"потери {pinger_stats['loss']:.1f}%"))
            self._safe_update(lambda: self.uptime_label.configure(text=self.sniffer.get_uptime()))
            
            thresholds = config.get("alert_thresholds", {})
            loss = pinger_stats['loss']
            
            if loss > thresholds.get("loss_critical", 5):
                alert_text, alert_color = "🚨 КРИТИЧЕСКИЕ ПОТЕРИ!", "#ff4757"
            elif loss > thresholds.get("loss_high", 2):
                alert_text, alert_color = "⚠️ Потери пакетов", "#ff4757"
            elif display_ping > thresholds.get("ping_high", 150):
                alert_text, alert_color = "⚠️ Высокий пинг", "#f1c40f"
            elif pinger_stats['jitter'] > thresholds.get("jitter_high", 30):
                alert_text, alert_color = "⚠️ Высокий джиттер", "#f1c40f"
            else:
                alert_text, alert_color = "✅ Сеть стабильна", "#2ed573"
            
            self._safe_update(lambda: self.alert_label.configure(text=alert_text, text_color=alert_color))
            self._safe_update(lambda: self.status_dot.configure(fg_color=alert_color))
            
            # AI Анализ
            if config.get("ai", {}).get("enabled", True):
                ai_data = {
                    "speed": speed,
                    "bytes_in": sniffer_stats['bytes_in_delta'],
                    "bytes_out": sniffer_stats['bytes_out_delta'],
                    "ping_ms": display_ping,
                    "jitter": pinger_stats['jitter'],
                    "loss": pinger_stats['loss']
                }
                
                ai_result = self.ai_orchestrator.process_traffic_data(ai_data)
                
                if ai_result.get('analysis', {}).get('is_anomaly', False):
                    confidence = ai_result['analysis'].get('confidence', 0)
                    severity = "HIGH" if confidence > 0.8 else "MEDIUM"
                    self._safe_update(lambda: self.alert_label.configure(
                        text=f"🤖 AI: Аномалия ({severity})",
                        text_color="#ff4757"
                    ))
            
            if not hasattr(self, '_chart_counter'):
                self._chart_counter = 0
            self._chart_counter = (self._chart_counter + 1) % 2
            
            if self._chart_counter == 0:
                speed_history = sniffer_stats['speed_history']
                ping_history = pinger_stats['history']
                
                self._safe_update(lambda: self.speed_chart.draw([(t, s) for t, s in speed_history]))
                self._safe_update(lambda: self.ping_chart.draw([(t, ms if ms is not None else None) for t, ms, loss in ping_history]))
            
            if not hasattr(self, '_ip_counter'):
                self._ip_counter = 0
            self._ip_counter = (self._ip_counter + 1) % 3
            
            if self._ip_counter == 0:
                self._update_ip_list()
            
            avg_stats = db_manager.execute(
                """SELECT 
                    (SELECT AVG(speed) FROM traffic WHERE timestamp > datetime('now','-1 hour')) as avg_speed,
                    (SELECT AVG(ping_ms) FROM pings WHERE timestamp > datetime('now','-1 hour') AND loss = 0 AND ping_ms IS NOT NULL) as avg_ping
                """,
                fetch=True
            )
            
            if avg_stats and len(avg_stats) > 0:
                avg_speed = avg_stats[0].get('avg_speed', 0) or 0
                avg_ping = avg_stats[0].get('avg_ping', 0) or 0
                self._safe_update(lambda: self.avg_label.configure(text=f"ср. {avg_speed:.1f} KB/s | {avg_ping:.0f}ms"))
            
        except Exception as e:
            logger.error(f"Ошибка обновления UI: {e}")
    
    def _update_ip_list(self):
        def update_ips():
            try:
                top_ips = self.sniffer.get_top_ips(6)
                self._safe_update(lambda: self._render_ip_list(top_ips))
            except Exception as e:
                logger.error(f"Ошибка получения IP: {e}")
        
        async_worker.submit(update_ips)
    
    def _render_ip_list(self, top_ips):
        try:
            for widget in self.ip_list.winfo_children():
                widget.destroy()
            
            if not top_ips:
                ctk.CTkLabel(self.ip_list, text="Нет активных подключений", text_color="#6a6a7a").pack(pady=10)
                return
            
            for ip, data in top_ips:
                row = ctk.CTkFrame(self.ip_list, fg_color="transparent")
                row.pack(fill="x", pady=1)
                
                ctk.CTkLabel(row, text=ip, font=ctk.CTkFont(size=10), text_color="#e0e0e0").pack(side="left")
                ctk.CTkLabel(row, text=f"{data['bytes']/1024:.0f} KB", font=ctk.CTkFont(size=10), text_color="#f1c40f").pack(side="right", padx=8)
                ctk.CTkLabel(row, text=f"{data['packets']} pkt", font=ctk.CTkFont(size=10), text_color="#6a6a7a").pack(side="right", padx=8)
        except Exception as e:
            logger.error(f"Ошибка рендеринга IP: {e}")
    
    def _open_ai_dashboard(self):
        if self.ai_dashboard is None or not self.ai_dashboard.win.winfo_exists():
            self.ai_dashboard = AIDashboard(self.root, self.ai_orchestrator)
        else:
            self.ai_dashboard.win.lift()
            self.ai_dashboard.win.focus_force()
    
    def _open_trace(self):
        if self.trace_window is None or not self.trace_window.winfo_exists():
            self.trace_window = TraceWindow(self.root)
        else:
            self.trace_window.win.lift()
            self.trace_window.win.focus_force()
    
    def _open_security(self):
        if self.security_window is None or not self.security_window.winfo_exists():
            self.security_window = SecurityWindow(self.root)
        else:
            self.security_window.win.lift()
            self.security_window.win.focus_force()
    
    def _export_report(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Текстовый файл", "*.txt")])
        if not path:
            return
        
        def export_worker():
            traffic = db_manager.execute(
                """SELECT timestamp, speed, bytes_in_delta, bytes_out_delta 
                FROM traffic ORDER BY timestamp DESC LIMIT 30""",
                fetch=True
            )
            pings = db_manager.execute(
                """SELECT timestamp, ping_ms, loss 
                FROM pings ORDER BY timestamp DESC LIMIT 30""",
                fetch=True
            )
            return traffic, pings
        
        def save_report(result):
            try:
                traffic, pings = result
                
                with open(path, "w", encoding="utf-8") as f:
                    f.write("=" * 60 + "\n")
                    f.write("ОТЧЁТ СЕТЕВОГО МОНИТОРИНГА\n")
                    f.write(f"Сгенерирован: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")
                    f.write("=" * 60 + "\n\n")
                    
                    f.write("📈 ТРАФИК\n")
                    f.write("-" * 40 + "\n")
                    if traffic:
                        for row in traffic:
                            ts = row['timestamp']
                            speed = row['speed']
                            bytes_in = row['bytes_in_delta'] or 0
                            bytes_out = row['bytes_out_delta'] or 0
                            f.write(f"{ts[11:19]} | {speed:8.1f} KB/s | in:{bytes_in/1024:8.1f} KB | out:{bytes_out/1024:8.1f} KB\n")
                    else:
                        f.write("Нет данных о трафике\n")
                    
                    f.write("\n📉 ПИНГ\n")
                    f.write("-" * 40 + "\n")
                    if pings:
                        last_good = None
                        for row in pings:
                            ts = row['timestamp']
                            ping_ms = row['ping_ms']
                            loss = row['loss']
                            
                            if loss:
                                display_ping = last_good if last_good is not None else 0
                                ping_display = f"{display_ping:4.0f}ms" if display_ping > 0 else "---"
                                f.write(f"{ts[11:19]} | {ping_display} | ПОТЕРЯ\n")
                            else:
                                ping_display = f"{ping_ms:4.0f}ms" if ping_ms and ping_ms > 0 else "---"
                                f.write(f"{ts[11:19]} | {ping_display}\n")
                                if ping_ms:
                                    last_good = ping_ms
                    else:
                        f.write("Нет данных о пинге\n")
                
                self._safe_update(lambda: self.alert_label.configure(text="✅ Отчёт сохранён", text_color="#2ed573"))
                messagebox.showinfo("Успех", f"Отчёт сохранён: {os.path.basename(path)}")
            except Exception as e:
                logger.error(f"Ошибка экспорта: {e}")
                messagebox.showerror("Ошибка", f"Не удалось сохранить отчёт: {e}")
        
        async_worker.submit(export_worker, callback=save_report)
    
    def run(self):
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            logger.info("Приложение остановлено пользователем")
        except Exception as e:
            logger.error(f"Критическая ошибка: {e}")
            raise

# ========== ЗАПУСК ==========
if __name__ == "__main__":
    try:
        app = App()
        app.run()
    except KeyboardInterrupt:
        print("\nОстановлено пользователем")
    except Exception as e:
        print(f"❌ КРИТИЧЕСКАЯ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        input("Нажмите Enter для выхода...")