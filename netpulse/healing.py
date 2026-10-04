"""Self-Healing: автоматические реакции на события через runbooks.

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

v3-реализация: тот же контракт Healing(service), типизировано.
service обязан давать .cfg (dict), .runbooks, .journal.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SKIP_SEVERITIES = {"LOW"}


class Healing:
    def __init__(self, service: Any):
        self.svc = service
        self._last_run: Dict[Tuple[int, str], float] = {}  # (rule_idx, host) -> ts

    def _cfg(self) -> Dict[str, Any]:
        base = {"enabled": False, "rules": []}
        cfg = dict(self.svc.cfg.get("healing", {}) or {})
        base.update(cfg)
        return base

    def _rate_ok(self, rule_idx: int, host: Optional[str], max_per_hour: int) -> bool:
        key = (rule_idx, host or "")
        now = time.time()
        last = self._last_run.get(key, 0)
        if now - last < 3600 / max(1, max_per_hour):
            return False
        self._last_run[key] = now
        return True

    def on_event(
        self,
        host_id: Optional[int],
        kind: str,
        severity: str,
        host_name: Optional[str] = None,
    ) -> None:
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
            if severity in SKIP_SEVERITIES:
                continue
            maxph = int(rule.get("max_per_hour") or 1)
            if not self._rate_ok(idx, host_name, maxph):
                continue
            self._fire_rule(rule, kind, host_name)

    def _fire_rule(self, rule: Dict[str, Any], kind: str, host_name: Optional[str]) -> None:
        rb = str(rule.get("runbook") or "")
        params = {"host": host_name} if host_name else {}
        try:
            res = self.svc.runbooks.execute(rb, params, actor="healing")
            logger.info("Self-Healing: %s -> %s: %s", kind, rb, res.get("ok"))
            self.svc.journal.add(
                text=f"⚙️ Self-Healing: событие {kind} → runbook "
                     f"{rb} ({'выполнен' if res.get('ok') else 'ошибка'})",
                source="runbook", host=host_name)
        except Exception as e:
            logger.warning("Self-Healing %s: %s", rb, e)

    def status_list(self) -> Dict[str, Any]:
        cfg = self._cfg()
        out = []
        for idx, rule in enumerate(cfg.get("rules") or []):
            if not isinstance(rule, dict):
                continue
            key = (idx, "")
            last_ts = self._last_run.get(key)
            out.append({
                "on_event": rule.get("on_event"),
                "runbook": rule.get("runbook"),
                "confirm": bool(rule.get("confirm")),
                "last_run": (datetime.fromtimestamp(last_ts).isoformat()
                             if last_ts else None),
            })
        return {"enabled": bool(cfg.get("enabled")), "rules": out}
