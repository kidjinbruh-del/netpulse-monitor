"""
Self-Healing: автоматические реакции на события через runbooks.

Правила задаются в config.json -> "healing": {
  "enabled": false,
  "rules": [
    {"on_event": "disk",       "runbook": "cleanup-temp",   "max_per_hour": 1},
    {"on_event": "offline",    "runbook": "restart-spooler", "max_per_hour": 1}
  ]
}

Предохранители:
- выполняются ТОЛЬКО зарегистрированные runbooks (никаких произвольных команд);
- не чаще max_per_hour на правило;
- каждый запуск — в audit_log и журнал работ;
- правило с "confirm": true требует ручного подтверждения и авто не исполняется.
"""

import json
import logging
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)


def _now_iso():
    return datetime.now().isoformat()


class Healing:
    def __init__(self, service):
        self.svc = service
        self._last_run = {}   # (rule_idx, host) -> ts

    def _cfg(self):
        base = {"enabled": False, "rules": []}
        cfg = dict(self.svc.cfg.get("healing") or {})
        base.update(cfg)
        return base

    def _rate_ok(self, rule_idx, host, max_per_hour):
        key = (rule_idx, host or "")
        now = time.time()
        last = self._last_run.get(key, 0)
        if now - last < 3600 / max(1, max_per_hour):
            return False
        self._last_run[key] = now
        return True

    def on_event(self, host_id, kind, severity, host_name=None):
        """Вызывается из inventory.note_event после записи события."""
        cfg = self._cfg()
        if not cfg.get("enabled"):
            return
        for idx, rule in enumerate(cfg.get("rules") or []):
            if not isinstance(rule, dict):
                continue
            if str(rule.get("on_event")) != str(kind):
                continue
            if rule.get("confirm"):
                continue
            if severity in ("LOW",):
                continue
            maxph = int(rule.get("max_per_hour") or 1)
            if not self._rate_ok(idx, host_name, maxph):
                continue
            rb = str(rule.get("runbook") or "")
            params = {"host": host_name} if host_name else {}
            try:
                res = self.svc.runbooks.execute(
                    rb, params, actor="healing")
                logger.info("Self-Healing: %s -> %s: %s",
                            kind, rb, res.get("ok"))
                self.svc.journal.add(
                    text=f"⚙️ Self-Healing: событие {kind} → runbook "
                         f"{rb} ({'выполнен' if res.get('ok') else 'ошибка'})",
                    source="runbook", host=host_name)
            except Exception as e:
                logger.warning("Self-Healing %s: %s", rb, e)

    def status_list(self):
        cfg = self._cfg()
        out = []
        for idx, r in enumerate(cfg.get("rules") or []):
            if not isinstance(r, dict):
                continue
            key = (idx, "")
            out.append({
                "on_event": r.get("on_event"),
                "runbook": r.get("runbook"),
                "confirm": bool(r.get("confirm")),
                "last_run": (datetime.fromtimestamp(self._last_run[key])
                             .isoformat() if key in self._last_run else None),
            })
        return {"enabled": bool(cfg.get("enabled")), "rules": out}
