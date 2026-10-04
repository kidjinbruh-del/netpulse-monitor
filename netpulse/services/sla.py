"""SLA service wrapper (backend: pending migration)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.sla")


class SlaService(BaseService):
    name = "sla"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        monitor = self.ctx.get_service("monitor")
        self._backend = monitor
        logger.info("SlaService attached to monitor")

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        attached = self._backend is not None and self._backend.legacy is not None
        return {"backend": "attached" if attached else "degraded"}

    def period(self, days: int = 30):
        if self._backend is None:
            return {"devices": [], "days": days}
        return self._backend.sla_period(days)
