"""
Database Manager - работа с SQLite
"""

import sqlite3
import queue
import threading
import time
import logging
from contextlib import contextmanager
from datetime import datetime

logger = logging.getLogger(__name__)

DB_PATH = "network_stats.db"
SCHEMA_VERSION = 2

class DatabaseManager:
    """Потокобезопасный менеджер БД с пулом соединений
    
    Все временные фильтры используют localtime: приложение пишет
    локальные timestamps (datetime.now()), а datetime('now') в SQLite - UTC.
    """
    
    ALLOWED_TABLES = {'traffic', 'pings', 'traces', 'alerts', 'security_log', 'ai_predictions'}
    
    def __init__(self, db_path=DB_PATH, pool_size=3):
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
        """Инициализация БД"""
        try:
            with self.connection() as conn:
                # Сначала создаём таблицы, затем мигрируем старые схемы
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
                
                # Миграция старых схем (добавление колонок) ДО создания индексов,
                # иначе индексы по новым колонкам упадут на старых таблицах
                self._migrate_tables(conn)

                conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_pings_ts ON pings(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_security_ts ON security_log(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_pings_target ON pings(target)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_predictions_ts ON ai_predictions(timestamp)")

                current_version = conn.execute("PRAGMA user_version").fetchone()[0]
                if current_version < SCHEMA_VERSION:
                    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                    logger.info(f"Схема БД обновлена: v{current_version} -> v{SCHEMA_VERSION}")

                conn.commit()
                logger.info("База данных инициализирована")
                return True
        except Exception as e:
            logger.error(f"Ошибка инициализации БД: {e}")
            return False
    
    def _migrate_tables(self, conn):
        """Миграция существующих таблиц (вызывается ПОСЛЕ их создания)"""
        try:
            # Проверяем и добавляем недостающие колонки
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
        """Выполнение запроса"""
        if self._closed:
            # Гонка на завершении приложения: тихо игнорируем вместо падения
            logger.debug("Запрос после закрытия DatabaseManager пропущен")
            return None
        
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
        """Массовое выполнение запросов"""
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
            days = 30  # По умолчанию
        
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
                        f"DELETE FROM {table} WHERE timestamp < datetime('now', 'localtime', ? || ' days')",
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
        if self._closed:
            return
        self._closed = True
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except Exception:
                    pass
                conn.close()
            except Exception:
                pass
        logger.info("DatabaseManager закрыт")