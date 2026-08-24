"""
Журнал работ отдела: быстрая фиксация звонков/визитов/задач + отчёты.
Источники записей: manual (руками), chat (переписка), watchdog (сторож ПК),
runbook (выполнение кнопок), backup (проверки бэкапов).
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def _now_iso():
    return datetime.now().isoformat()


class WorkJournal:
    """CRUD над таблицей journal + агрегированный отчёт за период."""

    def __init__(self, service):
        self.svc = service

    # ---------- запись ----------

    def add(self, text, source="manual", host=None, user_name=None, minutes=0):
        text = (text or "").strip()
        if not text:
            return {"ok": False, "error": "пустой текст записи"}
        try:
            minutes = max(0, int(minutes or 0))
        except (ValueError, TypeError):
            minutes = 0

        host_id = None
        if host:
            inv = getattr(self.svc, "inventory", None)
            if inv:
                try:
                    host_id = inv.resolve_host_id(str(host))
                except Exception:
                    host_id = None

        try:
            with self.svc.db.connection() as conn:
                cur = conn.execute(
                    """INSERT INTO journal
                       (timestamp, source, host_id, user_name, text, minutes)
                       VALUES (?,?,?,?,?,?)""",
                    (_now_iso(), str(source)[:16], host_id,
                     (str(user_name)[:80] if user_name else None),
                     text[:4000], minutes))
                jid = cur.lastrowid
                conn.commit()
        except Exception as e:
            logger.error("Журнал: %s", e)
            return {"ok": False, "error": "ошибка БД"}
        logger.info("Журнал +%s (%s, %s мин)", jid, source, minutes)
        return {"ok": True, "id": jid}

    def delete(self, entry_id):
        try:
            entry_id = int(entry_id)
        except (ValueError, TypeError):
            return {"ok": False, "error": "нужен числовой id"}
        n = self.svc.db.execute("DELETE FROM journal WHERE id = ?", (entry_id,))
        return {"ok": bool(n), "deleted": entry_id}

    # ---------- выборки ----------

    def list_entries(self, limit=150, source=None, q=None):
        limit = min(max(int(limit or 150), 1), 500)
        sql = """SELECT j.id, j.timestamp, j.source, j.user_name, j.text,
                        j.minutes, COALESCE(h.name, '') AS host
                 FROM journal j LEFT JOIN hosts h ON h.id = j.host_id"""
        where, params = [], []
        if source:
            where.append("j.source = ?")
            params.append(str(source)[:16])
        if q:
            where.append("(j.text LIKE ? OR j.user_name LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY j.id DESC LIMIT ?"
        params.append(limit)
        return self.svc.db.execute(sql, tuple(params), fetch=True) or []

    def month_report(self, days=30):
        try:
            days = min(max(int(days or 30), 1), 365)
        except (ValueError, TypeError):
            days = 30
        db = self.svc.db

        totals = db.execute(
            """SELECT COUNT(*) AS entries,
                      COALESCE(SUM(minutes), 0) AS minutes
               FROM journal
               WHERE timestamp > datetime('now','localtime', ? || ' days')""",
            (f"-{days}",), fetch=True) or [{}]
        totals = totals[0]

        by_source = db.execute(
            """SELECT source, COUNT(*) AS n, COALESCE(SUM(minutes),0) AS minutes
               FROM journal
               WHERE timestamp > datetime('now','localtime', ? || ' days')
               GROUP BY source ORDER BY n DESC""", (f"-{days}",),
            fetch=True) or []

        top_users = db.execute(
            """SELECT COALESCE(user_name,'(без имени)') AS who, COUNT(*) AS n,
                      COALESCE(SUM(minutes),0) AS minutes
               FROM journal
               WHERE timestamp > datetime('now','localtime', ? || ' days')
               GROUP BY who ORDER BY minutes DESC, n DESC LIMIT 7""",
            (f"-{days}",), fetch=True) or []

        top_hosts = db.execute(
            """SELECT COALESCE(h.name, '(не указана)') AS host,
                      COUNT(*) AS n, COALESCE(SUM(j.minutes),0) AS minutes
               FROM journal j LEFT JOIN hosts h ON h.id = j.host_id
               WHERE j.timestamp > datetime('now','localtime', ? || ' days')
               GROUP BY host ORDER BY n DESC LIMIT 7""",
            (f"-{days}",), fetch=True) or []

        per_day = db.execute(
            """SELECT date(timestamp) AS day, COUNT(*) AS n,
                      COALESCE(SUM(minutes),0) AS minutes
               FROM journal
               WHERE timestamp > datetime('now','localtime', ? || ' days')
               GROUP BY day ORDER BY day""", (f"-{days}",), fetch=True) or []

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
