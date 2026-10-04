import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from contextlib import contextmanager

from netpulse.config import DatabaseSettings
from netpulse.logging import get_logger


logger = get_logger("db")


class Database:
    """SQLite connection wrapper with thread safety and migrations."""
    
    def __init__(self, config: DatabaseSettings):
        self.config = config
        self._path = Path(config.path).resolve()
        self._local = threading.local()
        self._lock = threading.Lock()
        self._initialized = False
    
    def connect(self) -> None:
        """Initialize connection pool and run pragmas."""
        if self._initialized:
            return
        
        self._path.parent.mkdir(parents=True, exist_ok=True)
        
        # Test connection and setup
        with self._get_conn() as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            if self.config.wal_mode:
                conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA cache_size = -32768")  # 32MB
            conn.execute("PRAGMA temp_store = MEMORY")
            conn.execute("PRAGMA mmap_size = 268435456")  # 256MB
        
        self._initialized = True
        logger.info("Database connected", extra={"path": str(self._path)})
    
    @contextmanager
    def _get_conn(self):
        """Get thread-local connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self._path,
                check_same_thread=False,
                timeout=30.0
            )
            self._local.conn.row_factory = sqlite3.Row
        try:
            yield self._local.conn
        except Exception:
            self._local.conn.rollback()
            raise
    
    def execute(
        self,
        sql: str,
        params: Union[tuple, list] = (),
        fetch: bool = False,
        commit: bool = True
    ) -> Optional[List[Dict[str, Any]]]:
        """Execute SQL query."""
        with self._get_conn() as conn:
            cursor = conn.execute(sql, params)
            if commit:
                conn.commit()
            if fetch:
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            return cursor.lastrowid
    
    def executemany(self, sql: str, params_list: List[tuple]) -> None:
        """Execute many statements."""
        with self._get_conn() as conn:
            conn.executemany(sql, params_list)
            conn.commit()
    
    def execute_script(self, script: str) -> None:
        """Execute multiple statements from script."""
        with self._get_conn() as conn:
            conn.executescript(script)
            conn.commit()
    
    def migrate(self) -> None:
        """Run database migrations."""
        # Таблицы создаются сервисами при старте
        # Здесь только базовые таблицы для аудита и системных нужд
        self.execute_script("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT,
                ip TEXT,
                action TEXT NOT NULL,
                status INTEGER,
                details TEXT,
                request_id TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
        """)
        logger.debug("Base migrations applied")
    
    def close(self) -> None:
        """Close all connections."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
        self._initialized = False
        logger.info("Database closed")
    
    @property
    def path(self) -> Path:
        return self._path