"""Инвентарь парка: карточки машин, события и «карма» (health-score).

Карма = 100 минус штраф за события за окно 90 дней с затуханием по возрасту.

v3-реализация: тот же контракт Inventory(service), типизировано.
service обязан давать .db (execute/connection), опционально .push_alert/.healing.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SEVERITY_WEIGHT = {"CRITICAL": 8, "HIGH": 4, "MEDIUM": 2, "LOW": 1}
WINDOW_DAYS = 90


def _now_iso() -> str:
    return datetime.now().isoformat()


class Inventory:
    def __init__(self, service: Any):
        self.svc = service
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        db = self.svc.db
        db.execute(
            """CREATE TABLE IF NOT EXISTS karma_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                host_id INTEGER NOT NULL,
                score INTEGER)""")
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_karma_host ON karma_history(host_id)")
        # Миграция старых баз: железо в карточке машины.
        cols = [r["name"] for r in (db.execute(
            "PRAGMA table_info(hosts)", fetch=True) or [])]
        if cols:
            if "cpu" not in cols:
                db.execute("ALTER TABLE hosts ADD COLUMN cpu TEXT")
            if "ram_gb" not in cols:
                db.execute("ALTER TABLE hosts ADD COLUMN ram_gb REAL")

    # ---------- машины ----------

    def upsert_host(
        self, name: str, ip: str = "", os_info: str = ""
    ) -> Optional[int]:
        name = str(name or "").strip()
        if not name:
            return None
        db = self.svc.db
        row = db.execute("SELECT id FROM hosts WHERE name = ?", (name,), fetch=True)
        if row:
            hid = row[0]["id"]
            db.execute(
                """UPDATE hosts SET last_seen = ?, updated_at = ?,
                        ip = CASE WHEN ? <> '' THEN ? ELSE ip END,
                        os = CASE WHEN ? <> '' THEN ? ELSE os END
                   WHERE id = ?""",
                (_now_iso(), _now_iso(), ip, ip, os_info, os_info, hid))
            return hid
        try:
            with db.connection() as conn:
                cur = conn.execute(
                    """INSERT INTO hosts (name, ip, os, first_seen, last_seen,
                                          updated_at)
                       VALUES (?,?,?,?,?,?)""",
                    (name, ip, os_info, _now_iso(), _now_iso(), _now_iso()))
                conn.commit()
                return cur.lastrowid
        except Exception as e:
            logger.warning("upsert_host %s: %s", name, e)
            return None

    def resolve_host_id(self, name_or_ip: str) -> Optional[int]:
        key = str(name_or_ip or "").strip()
        if not key:
            return None
        row = self.svc.db.execute(
            "SELECT id FROM hosts WHERE name = ? OR ip = ?",
            (key, key), fetch=True)
        if row:
            return row[0]["id"]
        return self.upsert_host(key)

    def mark_online(self, host_id: int, online: bool) -> None:
        self.svc.db.execute(
            "UPDATE hosts SET online = ?, updated_at = ? WHERE id = ?",
            (1 if online else 0, _now_iso(), host_id))

    def list_hosts(self) -> List[Dict[str, Any]]:
        return self.svc.db.execute(
            """SELECT id, name, ip, os, online, health_score,
                      first_seen, last_seen, updated_at
               FROM hosts ORDER BY health_score ASC, name""", fetch=True) or []

    def host_detail(self, host_id: int) -> Dict[str, Any]:
        try:
            host_id = int(host_id)
        except (ValueError, TypeError):
            return {"error": "нужен числовой id"}
        host = self.svc.db.execute(
            "SELECT * FROM hosts WHERE id = ?", (host_id,), fetch=True)
        if not host:
            return {"error": "машина не найдена"}
        events = self.svc.db.execute(
            """SELECT timestamp, kind, severity, source, text FROM events
               WHERE host_id = ? ORDER BY id DESC LIMIT 50""",
            (host_id,), fetch=True) or []
        works = self.svc.db.execute(
            """SELECT timestamp, source, user_name, text, minutes FROM journal
               WHERE host_id = ? ORDER BY id DESC LIMIT 30""",
            (host_id,), fetch=True) or []
        detail = dict(host[0])
        detail["events"] = events
        detail["journal"] = works
        return detail

    # ---------- события ----------

    def note_event(
        self,
        host_id: Optional[int],
        kind: str,
        severity: str,
        source: str,
        text: str,
        dedup_key: Optional[str] = None,
        dedup_hours: int = 12,
    ) -> Dict[str, Any]:
        """Событие с дедупликацией по ключу в окне часов."""
        severity = severity if severity in SEVERITY_WEIGHT else "MEDIUM"
        db = self.svc.db
        if dedup_key:
            win = max(1, int(dedup_hours))
            dup = db.execute(
                """SELECT id FROM events
                   WHERE dedup_key = ?
                     AND timestamp > datetime('now','localtime', ? || ' hours')
                   LIMIT 1""",
                (dedup_key, f"-{win}"), fetch=True)
            if dup:
                return {"ok": True, "dedup": True}
        db.execute(
            """INSERT INTO events (timestamp, host_id, kind, severity, source,
                                   text, dedup_key)
               VALUES (?,?,?,?,?,?,?)""",
            (_now_iso(), host_id, str(kind)[:32], severity, str(source)[:16],
             (text or "")[:1000], dedup_key))

        label, host_name = "", None
        if host_id:
            h = db.execute("SELECT name FROM hosts WHERE id = ?",
                           (host_id,), fetch=True)
            if h:
                label = f" [{h[0]['name']}]"
                host_name = h[0]["name"]
        try:
            self.svc.push_alert(
                f"WATCH_{kind}".upper()[:40],
                f"{severity}: {text}{label}", source, rate=300)
        except Exception:
            pass
        try:
            healing = getattr(self.svc, "healing", None)
            if healing:
                healing.on_event(host_id, kind, severity, host_name)
        except Exception as e:
            logger.debug("healing: %s", e)
        return {"ok": True}

    def recent_events(
        self, limit: int = 80, host_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        limit = min(max(int(limit or 80), 1), 300)
        sql = """SELECT e.timestamp, e.kind, e.severity, e.source, e.text,
                        COALESCE(h.name,'') AS host
                 FROM events e LEFT JOIN hosts h ON h.id = e.host_id"""
        params: list = []
        if host_id:
            sql += " WHERE e.host_id = ?"
            params.append(int(host_id))
        sql += " ORDER BY e.id DESC LIMIT ?"
        params.append(limit)
        return self.svc.db.execute(sql, tuple(params), fetch=True) or []

    # ---------- карма ----------

    @staticmethod
    def _score_for_penalties(penalties: List[tuple]) -> int:
        """penalties: [(weight, age_days)] → score 0..100 с затуханием."""
        penalty = 0.0
        for weight, age in penalties:
            decay = max(0.0, 1.0 - max(0.0, float(age or 0)) / WINDOW_DAYS)
            penalty += weight * decay
        return max(0, min(100, round(100 - penalty)))

    def recompute_health(self) -> Dict[str, Any]:
        rows = self.svc.db.execute("SELECT id FROM hosts", fetch=True) or []
        changed = 0
        for r in rows:
            events = self.svc.db.execute(
                """SELECT severity,
                          julianday('now','localtime') - julianday(timestamp) AS age
                   FROM events
                   WHERE host_id = ?
                     AND timestamp > datetime('now','localtime','-90 days')""",
                (r["id"],), fetch=True) or []
            score = self._score_for_penalties([
                (SEVERITY_WEIGHT.get(e["severity"], 1), e["age"]) for e in events
            ])
            self.svc.db.execute(
                "UPDATE hosts SET health_score = ?, updated_at = ? WHERE id = ?",
                (score, _now_iso(), r["id"]))
            # Снапшот истории: не чаще раза в 6 часов на машину.
            if self._snapshot_due(r["id"]):
                self.svc.db.execute(
                    """INSERT INTO karma_history (timestamp, host_id, score)
                       VALUES (?,?,?)""", (_now_iso(), r["id"], score))
            changed += 1
        logger.info("Карма пересчитана для %s машин", changed)
        return {"ok": True, "hosts": changed}

    def _snapshot_due(self, host_id: int) -> bool:
        last = self.svc.db.execute(
            """SELECT timestamp FROM karma_history WHERE host_id = ?
               ORDER BY id DESC LIMIT 1""", (host_id,), fetch=True)
        if not last:
            return True
        try:
            age_h = ((datetime.now() - datetime.fromisoformat(last[0]["timestamp"]))
                     .total_seconds() / 3600.0)
            return age_h >= 6
        except Exception:
            return True

    def karma_history(self, host_id: int, limit: int = 120) -> List[int]:
        rows = self.svc.db.execute(
            """SELECT score FROM karma_history WHERE host_id = ?
               ORDER BY id DESC LIMIT ?""",
            (host_id, min(max(int(limit), 2), 400)), fetch=True) or []
        return [r["score"] for r in reversed(rows)]

    def worst_hosts(self, n: int = 5) -> List[Dict[str, Any]]:
        return self.svc.db.execute(
            """SELECT name, health_score, online FROM hosts
               ORDER BY health_score ASC LIMIT ?""",
            (min(max(int(n), 1), 20),), fetch=True) or []
