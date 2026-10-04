import logging
import json
import re
from datetime import datetime
from typing import Dict, Any, Optional

from netpulse.db.connection import Database


class AuditLogger:
    """Логирование аудита действий пользователей."""
    
    def __init__(self, db: Database):
        self.db = db
        self.logger = logging.getLogger("netpulse.audit")
    
    def log(
        self,
        action: str,
        user: str,
        ip: str,
        status: int,
        details: Dict[str, Any],
        request_id: Optional[str] = None
    ) -> None:
        """Записать событие аудита."""
        # Маскируем секреты
        safe_details = self._mask_secrets(details)
        
        # В БД
        try:
            self.db.execute(
                """INSERT INTO audit_log
                    (timestamp, user, ip, action, status, details, request_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    datetime.now().isoformat(),
                    user,
                    ip,
                    action,
                    status,
                    json.dumps(safe_details, ensure_ascii=False),
                    request_id
                )
            )
        except Exception as e:
            self.logger.error(f"Failed to write audit log: {e}")
        
        # Также в структурированный лог
        self.logger.info(
            "Audit event",
            extra={
                "audit": True,
                "action": action,
                "user": user,
                "ip": ip,
                "status": status,
                "details": safe_details,
                "request_id": request_id
            }
        )
    
    def _mask_secrets(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Маскировать секретные поля."""
        if not isinstance(data, dict):
            return {}
        
        result = {}
        secret_patterns = [
            r"token", r"password", r"secret", r"key", r"auth",
            r"credential", r"private"
        ]
        
        for key, value in data.items():
            key_lower = key.lower()
            is_secret = any(re.search(p, key_lower) for p in secret_patterns)
            
            if is_secret and isinstance(value, str) and value:
                result[key] = "***"
            elif isinstance(value, dict):
                result[key] = self._mask_secrets(value)
            elif isinstance(value, list):
                result[key] = [
                    self._mask_secrets(v) if isinstance(v, dict) else ("***" if is_secret else v)
                    for v in value
                ]
            else:
                result[key] = value
        return result
    
    def get_recent(self, limit: int = 100) -> list:
        """Получить последние записи аудита."""
        try:
            rows = self.db.execute(
                """SELECT timestamp, user, ip, action, status, details, request_id
                    FROM audit_log ORDER BY id DESC LIMIT ?""",
                (limit,), fetch=True
            )
            return rows or []
        except Exception:
            return []