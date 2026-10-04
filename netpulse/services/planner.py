"""Planner service wrapper (backend: legacy netpulse.planner)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.planner")


class PlannerService(BaseService):
    name = "planner"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        try:
            monitor = self.ctx.get_service("monitor")
            self._backend = monitor.planner_svc if monitor else None
            if self._backend is None:
                raise RuntimeError("monitor backend has no planner")
            logger.info("PlannerService attached to monitor backend")
        except Exception as e:
            logger.warning(f"PlannerService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {"backend": "attached" if self._backend else "degraded"}

    def status_list(self):
        if self._backend is None:
            return []
        return self._backend.status_list()

    def mark_done(self, name: str, actor: str = "admin"):
        if self._backend is None:
            return {"ok": False, "error": "backend unavailable"}
        return self._backend.mark_done(name, actor=actor)
