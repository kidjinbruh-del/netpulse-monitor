"""
Сторож бэкапов: следит, чтобы у каждого критичного ресурса была свежая копия.
Ресурсы задаются в config.json -> "backupwatch": {
  "enabled": true,
  "resources": [{"name": "База 1С", "path": "D:\\Backups\\1c", "interval_h": 24}]
}
Свежесть = mtime самого нового файла в каталоге (рекурсивно).
Протухло -> алерт + событие. Дополнительно напоминает о рестор-дрill раз
в месяц: если нет записи «drill» в журнале за 30 дней — мягкое напоминание.
"""

import logging
import os
import threading
from datetime import datetime

logger = logging.getLogger(__name__)


def _now_iso():
    return datetime.now().isoformat()


class BackupWatch:
    def __init__(self, service):
        self.svc = service
        self._stop = threading.Event()
        self._thread = None

    def _cfg(self):
        base = {"enabled": False, "resources": [], "drill_reminder": True}
        cfg = dict(self.svc.cfg.get("backupwatch", {}) or {})
        base.update(cfg)
        return base

    # ---------- проверка ----------

    def _newest_mtime(self, path):
        newest = 0
        if os.path.isfile(path):
            return os.path.getmtime(path)
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
            for f in files:
                try:
                    m = os.path.getmtime(os.path.join(root, f))
                    if m > newest:
                        newest = m
                except OSError:
                    continue
        return newest

    def check_once(self):
        cfg = self._cfg()
        results = []
        inv = self.svc.inventory
        for res in (cfg.get("resources") or []):
            name = str(res.get("name") or "").strip()
            path = str(res.get("path") or "").strip()
            try:
                interval_h = max(1, int(res.get("interval_h") or 24))
            except (ValueError, TypeError):
                interval_h = 24
            if not name or not path:
                continue

            try:
                mtime = self._newest_mtime(path)
                age_h = (datetime.now().timestamp() - mtime) / 3600.0 \
                    if mtime else None
            except Exception as e:
                mtime, age_h = 0, None
                logger.warning("Сторож бэкапов %s: %s", name, e)

            ok = bool(age_h is not None and age_h <= interval_h)
            last_ok_iso = (datetime.fromtimestamp(mtime).isoformat()
                           if mtime else None)

            exists = self.svc.db.execute(
                "SELECT id FROM backup_status WHERE resource = ?",
                (name,), fetch=True)
            if exists:
                self.svc.db.execute(
                    """UPDATE backup_status
                       SET path=?, interval_h=?, last_ok=COALESCE(?,last_ok), ok=?
                       WHERE resource=?""",
                    (path, interval_h, last_ok_iso, 1 if ok else 0, name))
            else:
                self.svc.db.execute(
                    """INSERT INTO backup_status
                       (resource, path, interval_h, last_ok, ok)
                       VALUES (?,?,?,?,?)""",
                    (name, path, interval_h, last_ok_iso, 1 if ok else 0))

            if not ok:
                msg = (f"Бэкап «{name}» протух: свежих файлов нет "
                       f"({age_h:.0f} ч)" if age_h is not None
                       else f"Бэкап «{name}»: каталог пуст/недоступен ({path})")
                try:
                    self.svc.push_alert("BACKUP_STALE", msg, "backupwatch",
                                        rate=3600 * 6)
                except Exception:
                    pass
                if inv:
                    hid = inv.resolve_host_id("server")
                    if hid:
                        inv.note_event(hid, "backup", "CRITICAL",
                                       "backupwatch", msg,
                                       dedup_key=f"backup:{name}:"
                                                 f"{datetime.now():%Y%m%d}",
                                       dedup_hours=12)
            results.append({"resource": name, "path": path,
                            "ok": ok,
                            "age_hours": round(age_h, 1) if age_h is not None
                            else None,
                            "last_backup": last_ok_iso})

        self._maybe_drill_reminder(cfg, results)
        return {"ok": True, "checked": len(results), "results": results}

    def _maybe_drill_reminder(self, cfg, results):
        """Раз в месяц напоминает проверить восстановление из копии."""
        if not cfg.get("drill_reminder", True) or datetime.now().day != 1:
            return
        recent = self.svc.db.execute(
            """SELECT id FROM journal
               WHERE timestamp > datetime('now','localtime','-31 days')
                 AND (text LIKE '%реставрац%' OR text LIKE '%восстановлен%'
                      OR text LIKE '%drill%' OR text LIKE '%учени%')
               LIMIT 1""", fetch=True)
        if not recent:
            try:
                self.svc.push_alert(
                    "BACKUP_DRILL",
                    "Пора провести учение: разверните бэкап и проверьте, "
                    "что данные живые", "backupwatch", rate=86400)
            except Exception:
                pass

    def status_list(self):
        rows = self.svc.db.execute(
            """SELECT resource, path, interval_h, last_ok, ok
               FROM backup_status ORDER BY ok ASC, resource""",
            fetch=True) or []
        return rows

    # ---------- жизненный цикл ----------

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop():
            while not self._stop.wait(10):
                try:
                    self.check_once()
                except Exception as e:
                    logger.warning("Цикл сторожа бэкапов: %s", e)
                # далее — раз в час
                self._stop.wait(3600)

        self._thread = threading.Thread(target=loop, daemon=True,
                                        name="np-backupwatch")
        self._thread.start()
        logger.info("Сторож бэкапов запущен")

    def stop(self):
        self._stop.set()
