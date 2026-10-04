"""Сторож бэкапов: следит, чтобы у каждого критичного ресурса была свежая копия.

Ресурсы задаются в config.json -> "backupwatch": {
  "enabled": true,
  "resources": [{"name": "База 1С", "path": "D:\\Backups\\1c", "interval_h": 24}]
}
Свежесть = mtime самого нового файла в каталоге (рекурсивно).
Протухло -> алерт + событие. Дополнительно напоминает о рестор-drill раз
в месяц: если нет записи «drill» в журнале за 30 дней — мягкое напоминание.

v3-реализация: тот же контракт BackupWatch(service), типизировано.
service обязан давать .cfg (dict), .db; опционально .inventory/.push_alert.
"""
from __future__ import annotations

import logging
import os
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

CHECK_DELAY_SEC = 10
RECHECK_INTERVAL_SEC = 3600
SKIP_DIRS = ("__pycache__", ".git")


def _now_iso() -> str:
    return datetime.now().isoformat()


class BackupWatch:
    def __init__(self, service: Any):
        self.svc = service
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _cfg(self) -> Dict[str, Any]:
        base = {"enabled": False, "resources": [], "drill_reminder": True}
        cfg = dict(self.svc.cfg.get("backupwatch", {}) or {})
        base.update(cfg)
        return base

    # ---------- проверка ----------

    @staticmethod
    def newest_mtime(path: str) -> float:
        """mtime самого нового файла (рекурсивно); 0 если пусто/нет доступа."""
        if os.path.isfile(path):
            try:
                return os.path.getmtime(path)
            except OSError:
                return 0
        newest = 0.0
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                try:
                    mtime = os.path.getmtime(os.path.join(root, name))
                    if mtime > newest:
                        newest = mtime
                except OSError:
                    continue
        return newest

    def check_once(self) -> Dict[str, Any]:
        cfg = self._cfg()
        results = []
        inv = getattr(self.svc, "inventory", None)
        for res in (cfg.get("resources") or []):
            name = str(res.get("name") or "").strip()
            path = str(res.get("path") or "").strip()
            try:
                interval_h = max(1, int(res.get("interval_h") or 24))
            except (ValueError, TypeError):
                interval_h = 24
            if not name or not path:
                continue
            mtime, age_h = self._check_resource(name, path)
            ok = bool(age_h is not None and age_h <= interval_h)
            last_ok_iso = (datetime.fromtimestamp(mtime).isoformat()
                           if mtime else None)
            self._upsert_status(name, path, interval_h, last_ok_iso, ok)
            if not ok:
                self._alert_stale(name, path, age_h, inv)
            results.append({"resource": name, "path": path,
                            "ok": ok,
                            "age_hours": round(age_h, 1) if age_h is not None
                            else None,
                            "last_backup": last_ok_iso})

        self._maybe_drill_reminder(cfg)
        return {"ok": True, "checked": len(results), "results": results}

    def _check_resource(self, name: str, path: str):
        try:
            mtime = self.newest_mtime(path)
            age_h = (datetime.now().timestamp() - mtime) / 3600.0 if mtime else None
        except Exception as e:
            logger.warning("Сторож бэкапов %s: %s", name, e)
            mtime, age_h = 0, None
        return mtime, age_h

    def _upsert_status(
        self, name: str, path: str, interval_h: int,
        last_ok_iso: Optional[str], ok: bool,
    ) -> None:
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

    def _alert_stale(
        self, name: str, path: str, age_h: Optional[float], inv: Any,
    ) -> None:
        if age_h is not None:
            msg = (f"Бэкап «{name}» протух: свежих файлов нет ({age_h:.0f} ч)")
        else:
            msg = f"Бэкап «{name}»: каталог пуст/недоступен ({path})"
        try:
            self.svc.push_alert("BACKUP_STALE", msg, "backupwatch", rate=3600 * 6)
        except Exception:
            pass
        if inv:
            try:
                hid = inv.resolve_host_id("server")
                if hid:
                    inv.note_event(hid, "backup", "CRITICAL", "backupwatch", msg,
                                   dedup_key=f"backup:{name}:{datetime.now():%Y%m%d}",
                                   dedup_hours=12)
            except Exception:
                pass

    def _maybe_drill_reminder(self, cfg: Dict[str, Any]) -> None:
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

    def status_list(self) -> List[Dict[str, Any]]:
        return self.svc.db.execute(
            """SELECT resource, path, interval_h, last_ok, ok
               FROM backup_status ORDER BY ok ASC, resource""",
            fetch=True) or []

    # ---------- жизненный цикл ----------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.wait(CHECK_DELAY_SEC):
                try:
                    self.check_once()
                except Exception as e:
                    logger.warning("Цикл сторожа бэкапов: %s", e)
                self._stop.wait(RECHECK_INTERVAL_SEC)

        self._thread = threading.Thread(target=loop, daemon=True,
                                        name="np-backupwatch")
        self._thread.start()
        logger.info("Сторож бэкапов запущен")

    def stop(self) -> None:
        self._stop.set()
