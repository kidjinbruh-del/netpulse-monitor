"""
AI Integration Module for Network Monitor Pro
Интеграция с Network Security AI Agent и Synapse
"""

import asyncio
import json
import time
import threading
from collections import deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# ========== КОНФИГУРАЦИЯ AI ==========
AI_CONFIG = {
    "anomaly_threshold": 0.6,
    "history_window": 100,
    "training_interval": 60,  # секунд
    "features": [
        "speed", "bytes_in", "bytes_out", 
        "packets_in", "packets_out", "ping_ms"
    ]
}

# ========== AI АГЕНТ ДЛЯ АНАЛИЗА ТРАФИКА ==========
class TrafficAIAgent:
    """AI агент для анализа сетевого трафика"""
    
    def __init__(self):
        self.model = None
        self.training_data = []
        self.anomalies = deque(maxlen=100)
        self.is_training = False
        self.last_training_time = 0
        
        # Статистика
        self.stats = {
            "total_analyzed": 0,
            "anomalies_detected": 0,
            "false_positives": 0,
            "avg_confidence": 0.0
        }
        
        logger.info("Traffic AI Agent инициализирован")
    
    def train(self, data: List[Dict]):
        """Обучение модели на исторических данных"""
        try:
            if len(data) < 10:
                return False
            
            self.is_training = True
            df = pd.DataFrame(data)
            
            # Выбираем числовые признаки
            features = AI_CONFIG["features"]
            available_features = [f for f in features if f in df.columns]
            
            if len(available_features) < 2:
                logger.warning("Недостаточно данных для обучения")
                return False
            
            X = df[available_features].values
            
            # Создаем и обучаем модель
            self.model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            self.model.fit(X)
            
            self.last_training_time = time.time()
            logger.info(f"Модель обучена на {len(X)} образцах")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка обучения модели: {e}")
            return False
        finally:
            self.is_training = False
    
    def analyze(self, data: Dict) -> Dict:
        """Анализ текущих данных на аномалии"""
        self.stats["total_analyzed"] += 1
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "is_anomaly": False,
            "confidence": 0.0,
            "score": 0.0,
            "features": {}
        }
        
        if not self.model:
            return result
        
        try:
            # Подготовка данных
            features = AI_CONFIG["features"]
            available_features = [f for f in features if f in data]
            
            if len(available_features) < 2:
                return result
            
            X = np.array([[data.get(f, 0) for f in available_features]])
            
            # Предсказание
            prediction = self.model.predict(X)
            score = self.model.score_samples(X)[0]
            
            # Нормализация скор
            normalized_score = 1 / (1 + np.exp(-score))
            
            result["score"] = float(normalized_score)
            result["features"] = {f: data.get(f, 0) for f in available_features}
            
            # Определение аномалии
            if prediction[0] == -1 and normalized_score > AI_CONFIG["anomaly_threshold"]:
                result["is_anomaly"] = True
                result["confidence"] = normalized_score
                self.stats["anomalies_detected"] += 1
                
                # Сохраняем аномалию
                anomaly_record = {
                    "timestamp": datetime.now().isoformat(),
                    "features": result["features"],
                    "confidence": normalized_score,
                    "data": data
                }
                self.anomalies.append(anomaly_record)
                
                logger.warning(f"Обнаружена аномалия! Уверенность: {normalized_score:.2f}")
            
            # Обновление средней уверенности
            current_avg = self.stats["avg_confidence"] * (self.stats["total_analyzed"] - 1)
            self.stats["avg_confidence"] = (current_avg + normalized_score) / self.stats["total_analyzed"]
            
        except Exception as e:
            logger.error(f"Ошибка анализа: {e}")
        
        return result
    
    def get_anomalies(self, limit=10) -> List[Dict]:
        """Получение последних аномалий"""
        return list(self.anomalies)[-limit:]
    
    def get_stats(self) -> Dict:
        """Получение статистики работы"""
        return {
            **self.stats,
            "model_trained": self.model is not None,
            "training_data_size": len(self.training_data),
            "anomalies_count": len(self.anomalies)
        }

# ========== AI АГЕНТ ДЛЯ ПРОГНОЗИРОВАНИЯ ==========
class PredictiveAgent:
    """AI агент для прогнозирования сетевых проблем"""
    
    def __init__(self):
        self.history = deque(maxlen=1000)
        self.predictions = deque(maxlen=100)
        self.trend_analysis = {}
        
        logger.info("Predictive AI Agent инициализирован")
    
    def update(self, data: Dict):
        """Обновление данных для прогнозирования"""
        self.history.append({
            "timestamp": time.time(),
            **data
        })
    
    def predict_next(self, metric: str = "speed", horizon: int = 10) -> Dict:
        """Прогнозирование следующего значения"""
        if len(self.history) < 20:
            return {"error": "Недостаточно данных для прогнозирования"}
        
        try:
            # Извлекаем историю для метрики
            values = [item.get(metric, 0) for item in self.history if metric in item]
            
            if len(values) < 10:
                return {"error": "Недостаточно данных для прогнозирования"}
            
            # Простое прогнозирование методом скользящей средней
            window = min(10, len(values) // 2)
            recent = values[-window:]
            avg = sum(recent) / len(recent)
            
            # Тренд
            if len(values) > window * 2:
                old_avg = sum(values[-window*2:-window]) / window
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
                "timestamp": datetime.now().isoformat()
            }
            
            self.predictions.append(prediction)
            return prediction
            
        except Exception as e:
            logger.error(f"Ошибка прогнозирования: {e}")
            return {"error": str(e)}
    
    def get_predictions(self) -> List[Dict]:
        """Получение всех прогнозов"""
        return list(self.predictions)

# ========== SYNAPSE ИНТЕГРАЦИЯ ==========
class SynapseAgent:
    """Агент для взаимодействия через Synapse сеть"""
    
    def __init__(self, name: str, capabilities: List[str]):
        self.name = name
        self.capabilities = capabilities
        self.connected = False
        self.peers = []
        self.tasks = deque(maxlen=100)
        
        logger.info(f"Synapse Agent '{name}' инициализирован")
    
    async def connect(self, hub_url: str):
        """Подключение к Synapse хабу"""
        try:
            # Имитация подключения
            self.connected = True
            logger.info(f"Synapse Agent '{self.name}' подключен к {hub_url}")
            return True
        except Exception as e:
            logger.error(f"Ошибка подключения Synapse: {e}")
            return False
    
    async def broadcast(self, message: Dict):
        """Широковещательная рассылка сообщения"""
        if not self.connected:
            return False
        
        try:
            # Имитация рассылки
            message["from"] = self.name
            message["timestamp"] = datetime.now().isoformat()
            logger.debug(f"Broadcast от {self.name}: {message.get('type', 'unknown')}")
            return True
        except Exception as e:
            logger.error(f"Ошибка broadcast: {e}")
            return False
    
    async def delegate_task(self, task: Dict, target_agent: str = None):
        """Делегирование задачи другому агенту"""
        if not self.connected:
            return False
        
        try:
            task["delegated_from"] = self.name
            task["delegated_to"] = target_agent or "any"
            task["timestamp"] = datetime.now().isoformat()
            
            self.tasks.append(task)
            logger.info(f"Задача делегирована: {task.get('type', 'unknown')}")
            return True
        except Exception as e:
            logger.error(f"Ошибка делегирования: {e}")
            return False
    
    def get_stats(self) -> Dict:
        return {
            "name": self.name,
            "connected": self.connected,
            "peers": len(self.peers),
            "pending_tasks": len(self.tasks),
            "capabilities": self.capabilities
        }

# ========== ИНТЕГРАЦИЯ С NETWORK MONITOR PRO ==========
class AIOrchestrator:
    """Оркестратор AI компонентов"""
    
    def __init__(self):
        self.traffic_agent = TrafficAIAgent()
        self.predictive_agent = PredictiveAgent()
        self.synapse_agent = None
        
        self._training_lock = threading.Lock()
        self._running = False
        
        logger.info("AI Orchestrator инициализирован")
    
    def initialize_synapse(self, agent_name: str = "network-monitor-pro"):
        """Инициализация Synapse агента"""
        capabilities = [
            "traffic_analysis",
            "anomaly_detection",
            "predictive_analysis",
            "security_monitoring"
        ]
        
        self.synapse_agent = SynapseAgent(agent_name, capabilities)
        
        # Запуск асинхронного подключения
        asyncio.create_task(self._connect_synapse())
        
        return self.synapse_agent
    
    async def _connect_synapse(self):
        """Асинхронное подключение к Synapse"""
        if self.synapse_agent:
            await self.synapse_agent.connect("wss://synapse-hub.example.com")
    
    def process_traffic_data(self, data: Dict) -> Dict:
        """Обработка данных трафика через AI"""
        # Обновляем данные для прогнозирования
        self.predictive_agent.update(data)
        
        # Анализ на аномалии
        analysis_result = self.traffic_agent.analyze(data)
        
        # Прогнозирование следующего значения
        prediction = self.predictive_agent.predict_next("speed")
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "analysis": analysis_result,
            "prediction": prediction,
            "stats": self.traffic_agent.get_stats()
        }
        
        # Если обнаружена аномалия - рассылаем через Synapse
        if analysis_result["is_anomaly"]:
            asyncio.create_task(self._broadcast_anomaly(analysis_result))
        
        return result
    
    async def _broadcast_anomaly(self, anomaly: Dict):
        """Широковещательная рассылка аномалии через Synapse"""
        if self.synapse_agent and self.synapse_agent.connected:
            message = {
                "type": "anomaly_detected",
                "severity": "high" if anomaly["confidence"] > 0.8 else "medium",
                "data": anomaly
            }
            await self.synapse_agent.broadcast(message)
    
    def train_model(self, historical_data: List[Dict]):
        """Обучение AI модели на исторических данных"""
        with self._training_lock:
            return self.traffic_agent.train(historical_data)
    
    def get_synapse_stats(self) -> Dict:
        """Получение статистики Synapse"""
        if self.synapse_agent:
            return self.synapse_agent.get_stats()
        return {"error": "Synapse не инициализирован"}
    
    def get_anomalies(self, limit: int = 10) -> List[Dict]:
        """Получение последних аномалий"""
        return self.traffic_agent.get_anomalies(limit)
    
    def get_predictions(self) -> List[Dict]:
        """Получение прогнозов"""
        return self.predictive_agent.get_predictions()
    
    def start_background_training(self):
        """Запуск фонового обучения модели"""
        self._running = True
        threading.Thread(target=self._background_training_loop, daemon=True).start()
    
    def _background_training_loop(self):
        """Фоновый цикл обучения"""
        while self._running:
            try:
                # Периодическое обучение модели на новых данных
                if self.traffic_agent.model:
                    # Обновление модели
                    pass
                time.sleep(60)
            except Exception as e:
                logger.error(f"Ошибка фонового обучения: {e}")
    
    def stop(self):
        """Остановка AI оркестратора"""
        self._running = False
        logger.info("AI Orchestrator остановлен")

# ========== ИНИЦИАЛИЗАЦИЯ ==========
ai_orchestrator = AIOrchestrator()

def init_ai_integration():
    """Инициализация AI интеграции"""
    logger.info("Запуск AI интеграции...")
    
    # Инициализация Synapse
    ai_orchestrator.initialize_synapse("network-monitor-pro")
    
    # Запуск фонового обучения
    ai_orchestrator.start_background_training()
    
    logger.info("AI интеграция активирована")
    return ai_orchestrator