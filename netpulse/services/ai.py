"""AI service wrapper (backend: pending migration, legacy требует модуль ai)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.ai")


class AIService(BaseService):
    name = "ai"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        if not self.config.ai.enabled:
            logger.info("AIService disabled in config")
            return
        try:
            monitor = self.ctx.get_service("monitor")
            self._backend = monitor.ai_svc if monitor else None
            if self._backend is None:
                raise RuntimeError("monitor backend has no ai")
            logger.info("AIService attached to monitor backend")
        except Exception as e:
            logger.warning(f"AIService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {
            "enabled": self.config.ai.enabled,
            "backend": "attached" if self._backend else "degraded",
        }

    def stats(self):
        if self._backend is None:
            return {"enabled": self.config.ai.enabled, "stats": {}}
        try:
            return self._backend.get_stats()
        except Exception:
            return {"enabled": self.config.ai.enabled, "stats": {}}

    def anomalies(self, limit: int = 15):
        if self._backend is None:
            return []
        try:
            return list(self._backend.get_anomalies(limit))
        except Exception:
            return []

    def predict(self, key: str = "speed"):
        if self._backend is None:
            return {}
        try:
            return self._backend.predictive_agent.predict_next(key)
        except Exception as e:
            return {"error": str(e)}

    def train(self, data) -> bool:
        if self._backend is None:
            return False
        try:
            return bool(self._backend.train_model(data))
        except Exception:
            return False
