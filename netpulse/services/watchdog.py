"""Watchdog service wrapper (backend: legacy netpulse.watchdog)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.watchdog")


class WatchdogService(BaseService):
    name = "watchdog"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        try:
            monitor = self.ctx.get_service("monitor")
            self._backend = monitor.watchdog_svc if monitor else None
            if self._backend is None:
                raise RuntimeError("monitor backend has no watchdog")
            logger.info("WatchdogService attached to monitor backend")
        except Exception as e:
            logger.warning(f"WatchdogService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {"backend": "attached" if self._backend else "degraded"}

    def status(self) -> Dict[str, Any]:
        base = super().status()
        if self._backend is not None:
            try:
                base.update(self._backend.status())
            except Exception:
                pass
        base["backend"] = "attached" if self._backend else "degraded"
        return base

    def poll_cycle(self):
        if self._backend is None:
            return {"error": "backend unavailable"}
        return self._backend.poll_cycle()

    def disk_forecast(self):
        if self._backend is None:
            return {"forecasts": []}
        try:
            return {"forecasts": self._backend.disk_forecast()}
        except Exception:
            return {"forecasts": []}
