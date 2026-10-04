"""DatabaseManager — потокобезопасная работа с SQLite (пул соединений).

Все временные фильтры используют localtime: приложение пишет
локальные timestamps (datetime.now()), а datetime('now') в SQLite — UTC.

v3-реализация: тот же контракт и поведение, типизировано.
"""
from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DB_PATH = "network_stats.db"
SCHEMA_VERSION = 3
DEFAULT_POOL_SIZE = 3
POOL_ACQUIRE_SEC = 5


class DatabaseManager:
    """Потокобезопасный менеджер БД с пулом соединений."""

    ALLOWED_TABLES = {"traffic", "pings", "traces", "alerts",
                      "security_log", "ai_predictions"}

    def __init__(self, db_path: str = DB_PATH, pool_size: int = DEFAULT_POOL_SIZE):
        self.db_path = db_path
        self._pool: queue.Queue = queue.Queue(maxsize=pool_size)
        self._lock = threading.RLock()
        self._closed = False
        self._metrics = {"queries": 0, "errors": 0, "pool_waits": 0.0}

        for i in range(pool_size):
            try:
                self._pool.put(self._create_connection())
                logger.debug("Соединение %s/%s создано", i + 1, pool_size)
            except Exception as e:
                logger.error("Ошибка создания соединения %s: %s", i + 1, e)

        if not self._pool.empty():
            self.init_db()

    def _create_connection(self) -> sqlite3.Connection:
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
                conn = self._pool.get(timeout=POOL_ACQUIRE_SEC)
            except queue.Empty:
                logger.warning("Пул соединений пуст, создаем временное")
                conn = self._create_connection()

            self._metrics["pool_waits"] += time.time() - start_time

            try:
                conn.execute("SELECT 1")
            except sqlite3.Error:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = self._create_connection()

            yield conn
        except Exception as e:
            logger.error("Ошибка получения соединения: %s", e)
            raise
        finally:
            if conn and not self._closed:
                try:
                    conn.rollback()
                    if self._pool.qsize() < self._pool.maxsize:
                        self._pool.put_nowait(conn)
                    else:
                        conn.close()
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass

    # ---------- схема ----------

    def init_db(self) -> bool:
        """Инициализация БД: таблицы, миграции, индексы, версия схемы."""
        try:
            with self.connection() as conn:
                # Сначала создаём таблицы, затем мигрируем старые схемы.
                for ddl in _BASE_SCHEMA:
                    conn.execute(ddl)
                # Миграция старых схем (добавление колонок) ДО создания
                # индексов, иначе индексы по новым колонкам упадут.
                self._migrate_tables(conn)
                for ddl in _BASE_INDEXES:
                    conn.execute(ddl)

                current_version = conn.execute(
                    "PRAGMA user_version").fetchone()[0]
                if current_version < SCHEMA_VERSION:
                    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                    logger.info("Схема БД обновлена: v%s -> v%s",
                                current_version, SCHEMA_VERSION)

                conn.commit()
                logger.info("База данных инициализирована")
                return True
        except Exception as e:
            logger.error("Ошибка инициализации БД: %s", e)
            return False

    def _migrate_tables(self, conn: sqlite3.Connection) -> None:
        """Добавление недостающих колонок в существующие таблицы."""
        try:
            migrations = {
                "pings": [("jitter", "REAL DEFAULT 0"),
                          ("target", "TEXT DEFAULT '8.8.8.8'")],
                "alerts": [("acknowledged", "INTEGER DEFAULT 0"),
                           ("source", "TEXT DEFAULT 'system'")],
                "traffic": [("bytes_in_delta", "INTEGER DEFAULT 0"),
                            ("bytes_out_delta", "INTEGER DEFAULT 0"),
                            ("anomaly_score", "REAL DEFAULT 0")],
                "security_log": [("resolved", "INTEGER DEFAULT 0")],
            }
            for table, columns in migrations.items():
                existing = [row[1] for row in
                            conn.execute(f"PRAGMA table_info({table})").fetchall()]
                for col, ddl in columns:
                    if col not in existing:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
            conn.commit()
        except Exception as e:
            logger.warning("Ошибка миграции таблиц: %s", e)

    # ---------- запросы ----------

    def execute(
        self, query: str, params: tuple = (),
        fetch: bool = False, retries: int = 3,
    ) -> Optional[Any]:
        if self._closed:
            # Гонка на завершении приложения: тихо игнорируем вместо падения.
            logger.debug("Запрос после закрытия DatabaseManager пропущен")
            return None

        self._metrics["queries"] += 1

        for attempt in range(retries):
            try:
                with self.connection() as conn:
                    cursor = conn.execute(query, params)
                    if fetch:
                        return [dict(row) for row in cursor.fetchall()]
                    conn.commit()
                    return cursor.rowcount
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < retries - 1:
                    time.sleep(0.1 * (2 ** attempt))
                    continue
                self._metrics["errors"] += 1
                logger.error("SQL ошибка: %s", e)
                return None
            except Exception as e:
                self._metrics["errors"] += 1
                logger.error("Ошибка выполнения: %s", e)
                return None
        return None

    def execute_many(
        self, query: str, params_list: list, retries: int = 3
    ) -> bool:
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
                logger.error("Ошибка массового выполнения: %s", e)
                return False
            except Exception as e:
                logger.error("Ошибка массового выполнения: %s", e)
                return False
        return False

    def cleanup_old_records(self, days: Optional[int] = None) -> bool:
        if self._closed:
            return False
        try:
            days = int(days) if days else 30
            if days < 1:
                days = 30
        except (ValueError, TypeError):
            days = 30

        try:
            with self.connection() as conn:
                deleted_total = 0
                for table in self.ALLOWED_TABLES:
                    cursor = conn.execute(
                        f"DELETE FROM {table} WHERE timestamp < "
                        f"datetime('now', 'localtime', ? || ' days')",
                        (f"-{days}",))
                    deleted_total += cursor.rowcount

                if deleted_total > 0:
                    conn.commit()
                    logger.info("Очищены записи старше %s дней (удалено: %s)",
                                days, deleted_total)
                    if deleted_total > 1000:
                        try:
                            conn.execute("VACUUM")
                            conn.commit()
                            logger.info("VACUUM выполнен")
                        except sqlite3.OperationalError as e:
                            if "cannot VACUUM" in str(e):
                                logger.warning(
                                    "VACUUM не выполнен (активна транзакция)")
                            else:
                                raise
                else:
                    logger.info("Нет записей для очистки (старше %s дней)", days)
                return True
        except Exception as e:
            logger.error("Ошибка очистки БД: %s", e)
            return False

    def get_metrics(self) -> Dict[str, Any]:
        return {
            **self._metrics,
            "pool_size": self._pool.qsize(),
            "pool_max": self._pool.maxsize,
        }

    def close(self) -> None:
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


_BASE_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        speed REAL,
        bytes_in INTEGER,
        bytes_out INTEGER,
        bytes_in_delta INTEGER DEFAULT 0,
        bytes_out_delta INTEGER DEFAULT 0,
        anomaly_score REAL DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS pings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        ping_ms REAL,
        loss INTEGER DEFAULT 0,
        jitter REAL DEFAULT 0,
        target TEXT DEFAULT '8.8.8.8'
    )""",
    """CREATE TABLE IF NOT EXISTS traces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        target TEXT,
        hops INTEGER,
        avg_ms REAL
    )""",
    """CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        alert_type TEXT,
        message TEXT,
        acknowledged INTEGER DEFAULT 0,
        source TEXT DEFAULT 'system'
    )""",
    """CREATE TABLE IF NOT EXISTS security_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        threat_type TEXT,
        severity TEXT,
        details TEXT,
        resolved INTEGER DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS ai_predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        metric TEXT,
        current_value REAL,
        predicted_value REAL,
        confidence REAL,
        trend REAL
    )""",
    # --- Платформа отдела (v3): парк, события, журнал, кнопки ---
    """CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        ip TEXT, os TEXT,
        first_seen TEXT, last_seen TEXT, updated_at TEXT,
        online INTEGER DEFAULT 0,
        health_score INTEGER DEFAULT 100
    )""",
    """CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        host_id INTEGER,
        kind TEXT, severity TEXT DEFAULT 'MEDIUM',
        source TEXT DEFAULT 'watchdog',
        text TEXT, dedup_key TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS journal (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source TEXT DEFAULT 'manual',
        host_id INTEGER,
        user_name TEXT,
        text TEXT NOT NULL,
        minutes INTEGER DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS runbook_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        runbook TEXT, params TEXT,
        actor TEXT DEFAULT 'admin', target TEXT,
        exit_code INTEGER, output TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS backup_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        resource TEXT UNIQUE NOT NULL,
        path TEXT, interval_h INTEGER DEFAULT 24,
        last_ok TEXT, ok INTEGER DEFAULT 0
    )""",
]

_BASE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_pings_ts ON pings(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_security_ts ON security_log(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_pings_target ON pings(target)",
    "CREATE INDEX IF NOT EXISTS idx_predictions_ts ON ai_predictions(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_host ON events(host_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_dedup ON events(dedup_key)",
    "CREATE INDEX IF NOT EXISTS idx_journal_ts ON journal(timestamp)",
]
