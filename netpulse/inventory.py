"""
Инвентарь парка: карточки машин, события и расчёт «кармы» (health-score).
Карта = 100 минус штраф за события за окно 90 дней с затуханием по возрасту.
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)

SEVERITY_WEIGHT = {"CRITICAL": 8, "HIGH": 4, "MEDIUM": 2, "LOW": 1}
WINDOW_DAYS = 90


def _now_iso():
    return datetime.now().isoformat()


class Inventory:
    def __init__(self, service):
        self.svc = service

    # ---------- машины ----------

    def upsert_host(self, name, ip="", os_info=""):
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

    def resolve_host_id(self, name_or_ip):
        key = str(name_or_ip or "").strip()
        if not key:
            return None
        row = self.svc.db.execute(
            "SELECT id FROM hosts WHERE name = ? OR ip = ?",
            (key, key), fetch=True)
        if row:
            return row[0]["id"]
        return self.upsert_host(key)

    def mark_online(self, host_id, online):
        self.svc.db.execute(
            "UPDATE hosts SET online = ?, updated_at = ? WHERE id = ?",
            (1 if online else 0, _now_iso(), host_id))

    def list_hosts(self):
        return self.svc.db.execute(
            """SELECT id, name, ip, os, online, health_score,
                      first_seen, last_seen, updated_at
               FROM hosts ORDER BY health_score ASC, name""", fetch=True) or []

    def host_detail(self, host_id):
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
        d = dict(host[0])
        d["events"] = events
        d["journal"] = works
        return d

    # ---------- события ----------

    def note_event(self, host_id, kind, severity, source, text,
                   dedup_key=None, dedup_hours=12):
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

        label = ""
        if host_id:
            h = db.execute("SELECT name FROM hosts WHERE id = ?",
                           (host_id,), fetch=True)
            label = f" [{h[0]['name']}]" if h else ""
        try:
            self.svc.push_alert(
                f"WATCH_{kind}".upper()[:40],
                f"{severity}: {text}{label}", source, rate=300)
        except Exception:
            pass
        return {"ok": True}

    def recent_events(self, limit=80, host_id=None):
        limit = min(max(int(limit or 80), 1), 300)
        sql = """SELECT e.timestamp, e.kind, e.severity, e.source, e.text,
                        COALESCE(h.name,'') AS host
                 FROM events e LEFT JOIN hosts h ON h.id = e.host_id"""
        params = []
        if host_id:
            sql += " WHERE e.host_id = ?"
            params.append(int(host_id))
        sql += " ORDER BY e.id DESC LIMIT ?"
        params.append(limit)
        return self.svc.db.execute(sql, tuple(params), fetch=True) or []

    # ---------- карма ----------

    def recompute_health(self):
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
            penalty = 0.0
            for e in events:
                w = SEVERITY_WEIGHT.get(e["severity"], 1)
                age = max(0.0, float(e["age"] or 0))
                decay = max(0.0, 1.0 - age / WINDOW_DAYS)
                penalty += w * decay
            score = max(0, min(100, round(100 - penalty)))
            self.svc.db.execute(
                "UPDATE hosts SET health_score = ?, updated_at = ? WHERE id = ?",
                (score, _now_iso(), r["id"]))
            changed += 1
        logger.info("Карма пересчитана для %s машин", changed)
        return {"ok": True, "hosts": changed}

    def worst_hosts(self, n=5):
        return self.svc.db.execute(
            """SELECT name, health_score, online FROM hosts
               ORDER BY health_score ASC LIMIT ?""",
            (min(max(int(n), 1), 20),), fetch=True) or []
