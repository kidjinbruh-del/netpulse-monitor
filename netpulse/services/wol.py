"""Wake-on-LAN service wrapper (backend: legacy netpulse.wol)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.wol")


class WolService(BaseService):
    name = "wol"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        try:
            from netpulse.wol import WolController
            monitor = self.ctx.get_service("monitor")
            legacy = monitor.legacy if monitor else None
            if legacy is None:
                raise RuntimeError("monitor backend unavailable")
            self._backend = WolController(legacy)
            logger.info("WolService attached to monitor backend")
        except Exception as e:
            logger.warning(f"WolService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {"backend": "attached" if self._backend else "degraded"}

    def wake(self, host):
        if self._backend is None:
            return {"ok": False, "error": "backend unavailable"}
        return self._backend.wake(host)
