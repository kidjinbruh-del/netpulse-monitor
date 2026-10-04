"""Proxmox service wrapper (backend: legacy netpulse.proxmox)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.proxmox")


class ProxmoxService(BaseService):
    name = "proxmox"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        if not self.config.proxmox.enabled:
            logger.info("ProxmoxService disabled in config")
            return
        try:
            monitor = self.ctx.get_service("monitor")
            self._backend = monitor.proxmox_svc if monitor else None
            if self._backend is None:
                raise RuntimeError("monitor backend has no proxmox")
            logger.info("ProxmoxService attached to monitor backend")
        except Exception as e:
            logger.warning(f"ProxmoxService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {
            "enabled": self.config.proxmox.enabled,
            "backend": "attached" if self._backend else "degraded",
        }

    def status(self):
        if self._backend is None:
            return {"enabled": False, "note": "backend degraded"}
        try:
            return self._backend.status()
        except Exception as e:
            return {"enabled": False, "error": str(e)}

    def poll(self):
        if self._backend is None:
            return {"error": "backend unavailable"}
        return self._backend.poll()
