"""CustomChecks service wrapper (backend: legacy netpulse.customchecks)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.customchecks")


class CustomChecksService(BaseService):
    name = "customchecks"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        try:
            monitor = self.ctx.get_service("monitor")
            self._backend = monitor.customchecks_svc if monitor else None
            if self._backend is None:
                raise RuntimeError("monitor backend has no customchecks")
            logger.info("CustomChecksService attached to monitor backend")
        except Exception as e:
            logger.warning(f"CustomChecksService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {"backend": "attached" if self._backend else "degraded"}

    def results(self):
        if self._backend is None:
            return {}
        try:
            return self._backend.results()
        except Exception:
            return {}

    def run_all(self, force: bool = False):
        if self._backend is None:
            return {"ok": False, "error": "backend unavailable"}
        return self._backend.run_all(force=force)
