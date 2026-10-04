"""Журнал работ отдела: фиксация звонков/визитов/задач + отчёты.

Источники записей: manual (руками), chat (переписка), watchdog (сторож ПК),
runbook (выполнение кнопок), backup (проверки бэкапов).

v3-реализация: тот же контракт WorkJournal(service), типизировано.
service обязан давать .db (execute/connection) и опционально .inventory.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MAX_TEXT_LEN = 4000
MAX_SOURCE_LEN = 16
MAX_USER_LEN = 80


def _now_iso() -> str:
    return datetime.now().isoformat()


class WorkJournal:
    """CRUD над таблицей journal + агрегированный отчёт за период."""

    def __init__(self, service: Any):
        self.svc = service

    # ---------- запись ----------

    def add(
        self,
        text: str,
        source: str = "manual",
        host: Optional[str] = None,
        user_name: Optional[str] = None,
        minutes: int = 0,
    ) -> Dict[str, Any]:
        text = (text or "").strip()
        if not text:
            return {"ok": False, "error": "пустой текст записи"}
        try:
            minutes = max(0, int(minutes or 0))
        except (ValueError, TypeError):
            minutes = 0

        host_id = self._resolve_host_id(host)

        try:
            with self.svc.db.connection() as conn:
                cur = conn.execute(
                    """INSERT INTO journal
                       (timestamp, source, host_id, user_name, text, minutes)
                       VALUES (?,?,?,?,?,?)""",
                    (_now_iso(), str(source)[:MAX_SOURCE_LEN], host_id,
                     (str(user_name)[:MAX_USER_LEN] if user_name else None),
                     text[:MAX_TEXT_LEN], minutes))
                jid = cur.lastrowid
                conn.commit()
        except Exception as e:
            logger.error("Журнал: %s", e)
            return {"ok": False, "error": "ошибка БД"}
        logger.info("Журнал +%s (%s, %s мин)", jid, source, minutes)
        return {"ok": True, "id": jid}

    def delete(self, entry_id: int) -> Dict[str, Any]:
        try:
            entry_id = int(entry_id)
        except (ValueError, TypeError):
            return {"ok": False, "error": "нужен числовой id"}
        n = self.svc.db.execute("DELETE FROM journal WHERE id = ?", (entry_id,))
        return {"ok": bool(n), "deleted": entry_id}

    # ---------- выборки ----------

    def list_entries(
        self,
        limit: int = 150,
        source: Optional[str] = None,
        q: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        limit = min(max(int(limit or 150), 1), 500)
        sql = """SELECT j.id, j.timestamp, j.source, j.user_name, j.text,
                        j.minutes, COALESCE(h.name, '') AS host
                 FROM journal j LEFT JOIN hosts h ON h.id = j.host_id"""
        where, params = [], []
        if source:
            where.append("j.source = ?")
            params.append(str(source)[:MAX_SOURCE_LEN])
        if q:
            where.append("(j.text LIKE ? OR j.user_name LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY j.id DESC LIMIT ?"
        params.append(limit)
        return self.svc.db.execute(sql, tuple(params), fetch=True) or []

    def month_report(self, days: int = 30) -> Dict[str, Any]:
        try:
            days = min(max(int(days or 30), 1), 365)
        except (ValueError, TypeError):
            days = 30
        db = self.svc.db
        window = (f"-{days}",)

        totals = db.execute(
            """SELECT COUNT(*) AS entries,
                      COALESCE(SUM(minutes), 0) AS minutes
               FROM journal
               WHERE timestamp > datetime('now','localtime', ? || ' days')""",
            window, fetch=True) or [{}]
        totals = totals[0]

        by_source = db.execute(
            """SELECT source, COUNT(*) AS n, COALESCE(SUM(minutes),0) AS minutes
               FROM journal
               WHERE timestamp > datetime('now','localtime', ? || ' days')
               GROUP BY source ORDER BY n DESC""", window, fetch=True) or []

        top_users = db.execute(
            """SELECT COALESCE(user_name,'(без имени)') AS who, COUNT(*) AS n,
                      COALESCE(SUM(minutes),0) AS minutes
               FROM journal
               WHERE timestamp > datetime('now','localtime', ? || ' days')
               GROUP BY who ORDER BY minutes DESC, n DESC LIMIT 7""",
            window, fetch=True) or []

        top_hosts = db.execute(
            """SELECT COALESCE(h.name, '(не указана)') AS host,
                      COUNT(*) AS n, COALESCE(SUM(j.minutes),0) AS minutes
               FROM journal j LEFT JOIN hosts h ON h.id = j.host_id
               WHERE j.timestamp > datetime('now','localtime', ? || ' days')
               GROUP BY host ORDER BY n DESC LIMIT 7""", window, fetch=True) or []

        per_day = db.execute(
            """SELECT date(timestamp) AS day, COUNT(*) AS n,
                      COALESCE(SUM(minutes),0) AS minutes
               FROM journal
               WHERE timestamp > datetime('now','localtime', ? || ' days')
               GROUP BY day ORDER BY day""", window, fetch=True) or []

        return {
            "days": days,
            "entries": totals.get("entries", 0),
            "minutes": totals.get("minutes", 0),
            "hours": round((totals.get("minutes") or 0) / 60.0, 1),
            "by_source": by_source,
            "top_users": top_users,
            "top_hosts": top_hosts,
            "per_day": per_day,
        }

    # ---------- внутреннее ----------

    def _resolve_host_id(self, host: Optional[str]) -> Optional[int]:
        if not host:
            return None
        inv = getattr(self.svc, "inventory", None)
        if not inv:
            return None
        try:
            return inv.resolve_host_id(str(host))
        except Exception:
            return None
