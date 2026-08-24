"""
Программный инвентарь: приём отчётов с машин (GPO-скрипт) и поиск.
Скрипт для GPO скачивается из дашборда: /api/gposcript -> inventory.ps1.

Отчёт (POST /api/invreport):
{
  "hostname": "PC-01", "user": "ivanov", "os": "...",
  "cpu": "...", "ram_gb": 16,
  "software": [{"name": "...", "version": "...", "publisher": "..."}]
}
Стратегия: полный срез по машине — старые записи машины удаляются.
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def _now_iso():
    return datetime.now().isoformat()


class SoftwareInventory:
    def __init__(self, service):
        self.svc = service
        self.svc.db.execute(
            """CREATE TABLE IF NOT EXISTS sw_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                name TEXT NOT NULL, version TEXT, publisher TEXT,
                seen TEXT)""")
        self.svc.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_sw_host ON sw_inventory(host_id)")
        self.svc.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_sw_name ON sw_inventory(name)")

    # ---------- приём отчёта ----------

    def receive_report(self, data):
        if not isinstance(data, dict):
            return (400, {"ok": False, "error": "нужен JSON-объект"})
        hostname = str(data.get("hostname") or "").strip()
        software = data.get("software")
        if not hostname or not isinstance(software, list):
            return (400, {"ok": False,
                          "error": "нужны hostname и список software"})
        hostname = hostname[:64]

        inv = self.svc.inventory
        hid = inv.upsert_host(
            hostname,
            ip=str(data.get("ip") or "")[:45],
            os_info=str(data.get("os") or "")[:120])

        db = self.svc.db
        try:
            with db.connection() as conn:
                conn.execute(
                    "UPDATE hosts SET cpu = COALESCE(NULLIF(?,''), cpu), "
                    "ram_gb = COALESCE(?, ram_gb), updated_at = ? WHERE id = ?",
                    (str(data.get("cpu") or ""), data.get("ram_gb"),
                     _now_iso(), hid))
                conn.execute("DELETE FROM sw_inventory WHERE host_id = ?", (hid,))
                rows = []
                for s in software[:500]:
                    if not isinstance(s, dict):
                        continue
                    name = str(s.get("name") or "").strip()[:160]
                    if not name:
                        continue
                    rows.append((hid, name,
                                 str(s.get("version") or "")[:60],
                                 str(s.get("publisher") or "")[:120]))
                conn.executemany(
                    """INSERT INTO sw_inventory
                       (host_id, name, version, publisher, seen)
                       VALUES (?,?,?,?,?)""",
                    [(h, n, v, p, _now_iso()) for h, n, v, p in rows])
                conn.commit()
                count = len(rows)
        except Exception as e:
            logger.warning("Отчёт инвентаря %s: %s", hostname, e)
            return (500, {"ok": False, "error": "ошибка записи"})

        inv.mark_online(hid, True)
        logger.info("Инвентарь %s: %d позиций ПО", hostname, count)
        return {"ok": True, "host": hostname, "packages": count}

    # ---------- выборки ----------

    def for_host(self, host_id, limit=300):
        return self.svc.db.execute(
            """SELECT name, version, publisher, seen FROM sw_inventory
               WHERE host_id = ? ORDER BY name LIMIT ?""",
            (host_id, min(max(int(limit), 1), 500)), fetch=True) or []

    def search(self, q, limit=100):
        q = f"%{(q or '').strip()}%"
        if q == "%%":
            return []
        return self.svc.db.execute(
            """SELECT s.name, s.version, s.publisher, h.name AS host,
                      h.ip, h.online
               FROM sw_inventory s JOIN hosts h ON h.id = s.host_id
               WHERE s.name LIKE ? OR s.publisher LIKE ?
               ORDER BY h.name, s.name LIMIT ?""",
            (q, q, min(max(int(limit), 1), 300)), fetch=True) or []

    def stats(self):
        rows = self.svc.db.execute(
            """SELECT COUNT(DISTINCT host_id) AS hosts,
                      COUNT(*) AS packages FROM sw_inventory""",
            fetch=True) or [{}]
        return rows[0]
