"""Traffic AI Agent — обнаружение аномалий в трафике (IsolationForest).

v3-реализация: та же логика и контракт, типизировано.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

DEFAULT_FEATURES = ["speed", "bytes_in", "ping_ms"]
MIN_TRAIN_SAMPLES = 10
MIN_TRAIN_FEATURES = 2


class TrafficAIAgent:
    """AI-агент для анализа сетевого трафика."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.features: List[str] = self.config.get("features", list(DEFAULT_FEATURES))
        self.anomaly_threshold: float = self.config.get("anomaly_threshold", 0.6)

        self.model: Optional[IsolationForest] = None
        self.scaler = StandardScaler()
        self.features_used: List[str] = []
        self.anomalies: Deque[Dict[str, Any]] = deque(maxlen=100)
        self.is_training = False
        self.last_training_time = 0.0
        self.is_enabled = self.config.get("enabled", True)

        self.stats = {
            "total_analyzed": 0,
            "anomalies_detected": 0,
            "avg_confidence": 0.0,
            "model_trained": False,
        }

        self._lock = threading.RLock()

        logger.info("Traffic AI Agent инициализирован")

    def train(self, data: List[Dict[str, Any]]) -> bool:
        """Обучение модели на исторических данных."""
        if not self.is_enabled:
            return False

        with self._lock:
            if self.is_training:
                return False

            try:
                if len(data) < MIN_TRAIN_SAMPLES:
                    return False

                self.is_training = True

                # Признаки фиксируем до обучения, чтобы analyze использовал
                # ровно тот же набор.
                df = pd.DataFrame(data)
                features_used = [f for f in self.features if f in df.columns]

                if len(features_used) < MIN_TRAIN_FEATURES:
                    logger.warning("Недостаточно признаков для обучения: %s",
                                   features_used)
                    return False

                X = df[features_used].fillna(0).astype(float).values
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)

                model = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=100,
                )
                model.fit(X_scaled)

                # Атомарная подмена модели (analyze может читать параллельно).
                self.model = model
                self.scaler = scaler
                self.features_used = features_used

                self.last_training_time = time.time()
                self.stats["model_trained"] = True

                logger.info("Модель обучена на %s образцах (признаки: %s)",
                            len(X), features_used)
                return True

            except Exception as e:
                logger.error("Ошибка обучения модели: %s", e)
                return False
            finally:
                self.is_training = False

    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Анализ текущих данных на аномалии."""
        result: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "is_anomaly": False,
            "confidence": 0.0,
            "score": 0.0,
            "features": {},
        }

        if not self.is_enabled:
            return result

        with self._lock:
            self.stats["total_analyzed"] += 1

            if not self.model or not self.features_used:
                return result

            try:
                # Используем ровно те признаки, на которых обучена модель
                # (иначе scaler.transform упадёт из-за другой размерности).
                X = np.array([[float(data.get(f, 0) or 0)
                               for f in self.features_used]])
                X_scaled = self.scaler.transform(X)

                prediction = self.model.predict(X_scaled)
                score = self.model.score_samples(X_scaled)[0]

                # Нормализация скора.
                normalized_score = 1 / (1 + np.exp(-score))

                result["score"] = float(normalized_score)
                result["features"] = {f: data.get(f, 0)
                                      for f in self.features_used}

                if prediction[0] == -1 and normalized_score > self.anomaly_threshold:
                    result["is_anomaly"] = True
                    result["confidence"] = normalized_score
                    self.stats["anomalies_detected"] += 1

                    self.anomalies.append({
                        "timestamp": datetime.now().isoformat(),
                        "features": result["features"],
                        "confidence": normalized_score,
                        "data": data,
                    })

                    logger.warning("Обнаружена аномалия! Уверенность: %.2f",
                                   normalized_score)

                # Обновление средней уверенности.
                current_avg = self.stats["avg_confidence"] * (
                    self.stats["total_analyzed"] - 1)
                self.stats["avg_confidence"] = (
                    current_avg + normalized_score) / self.stats["total_analyzed"]

            except Exception as e:
                logger.error("Ошибка анализа: %s", e)

            return result

    def get_anomalies(self, limit: int = 10) -> List[Dict[str, Any]]:
        return list(self.anomalies)[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        return self.stats

    def set_enabled(self, enabled: bool) -> None:
        self.is_enabled = enabled
        logger.info("Traffic AI Agent %s",
                    "включен" if enabled else "отключен")
