"""Квоты трафика (NetWorx идея): использование день/месяц + алерты.

v3-реализация: тот же контракт QuotaManager(service), типизировано.
service обязан давать .db и .cfg (dict); опционально .push_alert.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict

logger = logging.getLogger(__name__)

CACHE_TTL_SEC = 60
BYTES_PER_MB = 1048576
BYTES_PER_GB = 1073741824


class QuotaManager:
    def __init__(self, service: Any):
        self.svc = service
        self._cache: Dict[str, Any] = {"ts": 0, "data": None}

    def usage(self) -> Dict[str, Any]:
        now = time.time()
        if self._cache["data"] and now - self._cache["ts"] < CACHE_TTL_SEC:
            return self._cache["data"]

        day = self.svc.db.execute(
            """SELECT SUM(bytes_in_delta + bytes_out_delta) AS b FROM traffic
               WHERE timestamp > datetime('now','localtime','start of day')""",
            fetch=True)
        month = self.svc.db.execute(
            """SELECT SUM(bytes_in_delta + bytes_out_delta) AS b FROM traffic
               WHERE timestamp > datetime('now','localtime','start of month')""",
            fetch=True)

        q = self.svc.cfg.get("quota", {})
        daily_used_mb = ((day[0]["b"] or 0) if day else 0) / BYTES_PER_MB
        monthly_used_gb = (((month[0]["b"] or 0) if month else 0)
                           / BYTES_PER_GB)

        daily_limit = float(q.get("daily_mb") or 0)
        monthly_limit = float(q.get("monthly_gb") or 0)

        data = {
            "daily_used_mb": round(daily_used_mb, 1),
            "daily_limit_mb": daily_limit,
            "daily_pct": round(100 * daily_used_mb / daily_limit, 1)
            if daily_limit else None,
            "monthly_used_gb": round(monthly_used_gb, 3),
            "monthly_limit_gb": monthly_limit,
            "monthly_pct": round(100 * monthly_used_gb / monthly_limit, 1)
            if monthly_limit else None,
        }
        warn = float(q.get("warn_pct", 80))

        self._check_limits(data, daily_limit, monthly_limit, warn)

        self._cache = {"ts": now, "data": data}
        return data

    def _check_limits(
        self, data: Dict[str, Any],
        daily_limit: float, monthly_limit: float, warn: float,
    ) -> None:
        try:
            push = self.svc.push_alert
        except Exception:
            return

        def alert(*args, **kwargs):
            try:
                push(*args, **kwargs)
            except Exception:
                pass

        if daily_limit and data["daily_pct"] >= 100:
            alert("QUOTA_DAY", "Дневной лимит трафика исчерпан!",
                  "quota", rate=3600)
        elif daily_limit and data["daily_pct"] >= warn:
            alert("QUOTA_DAY",
                  f"Использовано {data['daily_pct']}% дневного лимита",
                  "quota", rate=3600)

        if monthly_limit and data["monthly_pct"] >= 100:
            alert("QUOTA_MONTH", "Месячный лимит трафика исчерпан!",
                  "quota", rate=21600)
        elif monthly_limit and data["monthly_pct"] >= warn:
            alert("QUOTA_MONTH",
                  f"Использовано {data['monthly_pct']}% месячного лимита",
                  "quota", rate=21600)
