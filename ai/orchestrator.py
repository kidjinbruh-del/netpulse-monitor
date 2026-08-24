"""
AI Orchestrator - управление AI компонентами
"""

import threading
import time
import logging
from datetime import datetime

from .traffic_agent import TrafficAIAgent
from .predictive_agent import PredictiveAgent
from .synapse_agent import SynapseAgent

logger = logging.getLogger(__name__)

class AIOrchestrator:
    """Оркестратор AI компонентов"""
    
    def __init__(self, config=None, db_callback=None, alert_callback=None, data_provider=None):
        self.config = config or {}
        self.db_callback = db_callback
        self.alert_callback = alert_callback
        # Провайдер обучающих данных: callable -> list[dict]
        self.data_provider = data_provider
        
        # Инициализация агентов
        self.traffic_agent = TrafficAIAgent(self.config.get('traffic', {}))
        self.predictive_agent = PredictiveAgent(self.config.get('predictive', {}))
        self.synapse_agent = None
        
        self._running = False
        self._stop_event = threading.Event()
        self._training_lock = threading.Lock()
        self._thread = None
        self._event_callbacks = []
        
        logger.info("AI Orchestrator инициализирован")
    
    def _synapse_cfg(self):
        """Конфиг Synapse: поддержка вложенного 'synapse' и плоских ключей"""
        cfg = self.config.get('synapse')
        if isinstance(cfg, dict) and cfg:
            return {
                'enabled': cfg.get('enabled', True),
                'agent_name': cfg.get('agent_name', 'network-monitor-pro'),
                'hub_url': cfg.get('hub_url', 'wss://synapse-hub.example.com'),
            }
        return {
            'enabled': self.config.get('synapse_enabled', True),
            'agent_name': self.config.get('agent_name', 'network-monitor-pro'),
            'hub_url': self.config.get('hub_url', 'wss://synapse-hub.example.com'),
        }
    
    def initialize_synapse(self):
        """Инициализация Synapse агента"""
        syn_cfg = self._synapse_cfg()
        if not syn_cfg['enabled']:
            return None
        
        capabilities = ["traffic_analysis", "anomaly_detection", "predictive_analysis"]
        
        self.synapse_agent = SynapseAgent(syn_cfg['agent_name'], capabilities)
        self.synapse_agent.connect(syn_cfg['hub_url'])
        
        return self.synapse_agent
    
    def register_callback(self, callback):
        """Регистрация callback для событий"""
        self._event_callbacks.append(callback)
    
    def _trigger_callbacks(self, event_type, data):
        """Вызов всех зарегистрированных callback'ов"""
        for callback in self._event_callbacks:
            try:
                callback(event_type, data)
            except Exception as e:
                logger.error(f"Ошибка в callback: {e}")
    
    def process_traffic_data(self, data):
        """Обработка данных трафика через AI"""
        result = {
            "timestamp": datetime.now().isoformat(),
            "analysis": {},
            "prediction": {},
            "stats": {}
        }
        
        # Обновляем данные для прогнозирования
        self.predictive_agent.update(data)
        
        # Анализ на аномалии
        analysis_result = self.traffic_agent.analyze(data)
        result["analysis"] = analysis_result
        
        # Прогнозирование
        prediction = self.predictive_agent.predict_next("speed")
        result["prediction"] = prediction
        result["stats"] = self.traffic_agent.get_stats()
        
        # Если обнаружена аномалия
        if analysis_result.get("is_anomaly", False):
            # Вызываем alert callback
            if self.alert_callback:
                self.alert_callback(analysis_result)
            
            # Рассылаем через Synapse
            if self.synapse_agent and self.synapse_agent.connected:
                self.synapse_agent.broadcast({
                    "type": "anomaly_detected",
                    "severity": "high" if analysis_result.get("confidence", 0) > 0.8 else "medium",
                    "data": analysis_result
                })
            
            # Сохраняем в БД через callback
            if self.db_callback:
                self.db_callback("anomaly", analysis_result)
        
        # Триггерим событие
        self._trigger_callbacks("processed", result)
        
        return result
    
    def train_model(self, historical_data):
        """Обучение модели на исторических данных"""
        with self._training_lock:
            return self.traffic_agent.train(historical_data)
    
    def start_background_training(self, interval=None):
        """Запуск фонового обучения"""
        if self._running:
            return
        
        self._running = True
        if interval is None:
            interval = self.config.get('training_interval', 300)
        
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._background_training_loop,
            args=(interval,),
            daemon=True,
            name="AITrainingThread"
        )
        self._thread.start()
        logger.info(f"Фоновое обучение AI запущено (интервал: {interval}с)")
    
    def _fetch_training_data(self):
        """Получение обучающих данных через провайдер"""
        if not self.data_provider:
            return None
        try:
            return self.data_provider()
        except Exception as e:
            logger.error(f"Ошибка получения обучающих данных: {e}")
            return None
    
    def _background_training_loop(self, interval):
        """Фоновый цикл обучения"""
        # Первая итерация сразу, далее по интервалу
        while self._running and not self._stop_event.is_set():
            try:
                data = self._fetch_training_data()
                if data and len(data) >= 10:
                    self.traffic_agent.train(data)
                
                self._stop_event.wait(interval)
            except Exception as e:
                logger.error(f"Ошибка фонового обучения: {e}")
                self._stop_event.wait(60)
    
    def get_anomalies(self, limit=10):
        """Получение последних аномалий"""
        return self.traffic_agent.get_anomalies(limit)
    
    def get_predictions(self, limit=10):
        """Получение прогнозов"""
        return self.predictive_agent.get_predictions(limit)
    
    def get_stats(self):
        """Получение статистики работы"""
        return {
            "traffic": self.traffic_agent.get_stats(),
            "predictive": self.predictive_agent.get_stats(),
            "synapse": self.synapse_agent.get_stats() if self.synapse_agent else None,
            "running": self._running
        }
    
    def stop(self):
        """Остановка оркестратора"""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        logger.info("AI Orchestrator остановлен")
    
    def set_enabled(self, enabled):
        """Включение/отключение всех агентов"""
        self.traffic_agent.set_enabled(enabled)
        self.predictive_agent.set_enabled(enabled)
        if self.synapse_agent:
            self.synapse_agent.set_enabled(enabled)
        logger.info(f"AI Orchestrator {'включен' if enabled else 'отключен'}")