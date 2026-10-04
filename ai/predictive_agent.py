"""Predictive AI Agent — прогнозирование сетевых проблем (тренд по окну).

v3-реализация: та же логика и контракт, типизировано.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any, Callable, Deque, Dict, List, Optional

logger = logging.getLogger(__name__)

MIN_HISTORY = 10


class PredictiveAgent:
    """AI-агент для прогнозирования сетевых проблем."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.history: Deque[Dict[str, Any]] = deque(
            maxlen=self.config.get("history_window", 1000))
        self.predictions: Deque[Dict[str, Any]] = deque(maxlen=100)
        self.is_enabled = self.config.get("enabled", True)
        self._lock = threading.RLock()

        logger.info("Predictive AI Agent инициализирован")

    def update(self, data: Dict[str, Any]) -> None:
        """Обновление данных для прогнозирования."""
        if not self.is_enabled:
            return
        with self._lock:
            self.history.append({"timestamp": time.time(), **data})

    def predict_next(
        self, metric: str = "speed", horizon: int = 10
    ) -> Dict[str, Any]:
        """Прогнозирование следующего значения."""
        if not self.is_enabled:
            return {"error": "Агент отключен"}

        with self._lock:
            if len(self.history) < MIN_HISTORY:
                return {"error": "Недостаточно данных для прогнозирования"}

            try:
                values = [item.get(metric, 0) for item in self.history
                          if metric in item]

                if len(values) < MIN_HISTORY:
                    return {"error": "Недостаточно данных"}

                window = min(10, len(values) // 2)
                recent = values[-window:]
                avg = sum(recent) / len(recent)

                if len(values) > window * 2:
                    old_avg = sum(values[-window * 2:-window]) / window
                    trend = (avg - old_avg) / old_avg if old_avg > 0 else 0
                else:
                    trend = 0

                prediction = {
                    "metric": metric,
                    "current": values[-1] if values else 0,
                    "predicted": avg * (1 + trend * 0.5),
                    "trend": trend,
                    "confidence": 1.0 - (1.0 / (1 + len(values) / 10)),
                    "horizon": horizon,
                    "timestamp": datetime.now().isoformat(),
                }

                self.predictions.append(prediction)
                return prediction

            except Exception as e:
                logger.error("Ошибка прогнозирования: %s", e)
                return {"error": str(e)}

    def get_predictions(self, limit: int = 10) -> List[Dict[str, Any]]:
        return list(self.predictions)[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "history_size": len(self.history),
                "predictions_count": len(self.predictions),
                "is_enabled": self.is_enabled,
            }

    def set_enabled(self, enabled: bool) -> None:
        self.is_enabled = enabled
        logger.info("Predictive AI Agent %s",
                    "включен" if enabled else "отключен")
