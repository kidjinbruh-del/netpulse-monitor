"""Плановые работы: повторяющиеся задачи отдела (тонер, UPS, сертификаты).

Список в config.json -> "planner": {
  "enabled": true,
  "tasks": [{"name": "Проверить тонер", "every_days": 14}, ...]
}
Выполнение отмечается кнопкой из дашборда -> запись в журнал + дата.
Просрочено -> алерт (не чаще раза в сутки) и строка «просрочено» в UI.

v3-реализация: тот же контракт Planner(service), типизировано.
service обязан давать .cfg (dict), .db, .journal; опционально .push_alert.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

CHECK_INTERVAL_SEC = 60
RECHECK_INTERVAL_SEC = 3600


def _now_iso() -> str:
    return datetime.now().isoformat()


class Planner:
    def __init__(self, service: Any):
        self.svc = service
        self.svc.db.execute(
            """CREATE TABLE IF NOT EXISTS planner_state (
                name TEXT PRIMARY KEY,
                last_done TEXT NOT NULL)""")
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _cfg(self) -> Dict[str, Any]:
        base = {"enabled": False, "tasks": []}
        cfg = dict(self.svc.cfg.get("planner", {}) or {})
        base.update(cfg)
        return base

    # ---------- состояние задач ----------

    def _state(self, name: str) -> Optional[str]:
        row = self.svc.db.execute(
            "SELECT last_done FROM planner_state WHERE name = ?",
            (name,), fetch=True)
        return row[0]["last_done"] if row else None

    def mark_done(self, name: str, actor: Optional[str] = None) -> Dict[str, Any]:
        tasks = {t.get("name") for t in self._cfg().get("tasks") or []}
        if name not in tasks:
            return {"ok": False, "error": "задача не найдена в planner.tasks"}
        now = _now_iso()
        exists = self.svc.db.execute(
            "SELECT name FROM planner_state WHERE name = ?", (name,), fetch=True)
        if exists:
            self.svc.db.execute(
                "UPDATE planner_state SET last_done = ? WHERE name = ?",
                (now, name))
        else:
            self.svc.db.execute(
                "INSERT INTO planner_state (name, last_done) VALUES (?,?)",
                (name, now))
        journal_result = self.svc.journal.add(
            text=f"✓ Плановая работа: {name}", source="manual",
            user_name=actor or "admin")
        try:
            self.svc.push_alert("PLANNER_DONE", f"Выполнено: {name}",
                                "planner", rate=60)
        except Exception:
            pass
        return {"ok": True, "journal": journal_result}

    def status_list(self) -> List[Dict[str, Any]]:
        out = []
        for task in (self._cfg().get("tasks") or []):
            name = str(task.get("name") or "").strip()
            if not name:
                continue
            try:
                every = max(1, int(task.get("every_days") or 30))
            except (ValueError, TypeError):
                every = 30
            last_done = self._state(name)
            days_left: Optional[int] = -1  # ни разу не выполнялась
            if last_done:
                try:
                    days_left = every - (datetime.now()
                                         - datetime.fromisoformat(last_done)).days
                except Exception:
                    days_left = None
            due = days_left is not None and days_left <= 0
            out.append({"name": name, "every_days": every,
                        "last_done": last_done, "days_left": days_left,
                        "due": due})
        return sorted(out, key=lambda x: x["days_left"]
                      if x["days_left"] is not None else -999)

    def check_alerts(self) -> None:
        """Алерты по просроченным. Вызывается по расписанию."""
        for task in self.status_list():
            if task["due"]:
                try:
                    self.svc.push_alert(
                        "PLANNER_DUE",
                        f"Плановая работа просрочена: {task['name']} "
                        f"(каждые {task['every_days']} дн)",
                        "planner", rate=86400)
                except Exception:
                    pass

    # ---------- жизненный цикл ----------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.wait(CHECK_INTERVAL_SEC):
                try:
                    self.check_alerts()
                except Exception as e:
                    logger.warning("Планировщик: %s", e)
                self._stop.wait(RECHECK_INTERVAL_SEC)

        self._thread = threading.Thread(target=loop, daemon=True, name="np-planner")
        self._thread.start()
        logger.info("Планировщик плановых работ запущен")

    def stop(self) -> None:
        self._stop.set()
