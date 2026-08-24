"""
Network Monitor Pro v7.0 - AI Enterprise Edition
Точка входа в приложение
"""

import sys
import os
import json
import logging
import time
import atexit
from datetime import datetime

from core import DatabaseManager, Sniffer, Pinger
from ai import AIOrchestrator
from ui import App

# Настройка логирования
def setup_logging():
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, f"network_monitor_{datetime.now().strftime('%Y%m%d')}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)

logger = setup_logging()

# Загрузка конфига
def load_config():
    config_file = "config.json"
    default_config = {
        "ping_target": "8.8.8.8",
        "theme": "dark",
        "update_interval": 1000,
        "db_cleanup_days": 30,
        "max_buffer_size": 1000,
        "sniffer_timeout": 1,
        "dns_timeout": 3,
        "ai": {
            "enabled": True,
            "anomaly_threshold": 0.6,
            "training_interval": 300,
            "features": ["speed", "bytes_in", "ping_ms"],
            "synapse_enabled": True,
            "hub_url": "wss://synapse-hub.example.com",
            "agent_name": "network-monitor-pro"
        },
        "alert_thresholds": {
            "ping_high": 150,
            "loss_high": 2,
            "jitter_high": 30,
            "loss_critical": 5
        },
        "targets": {
            "dns": ["8.8.8.8", "1.1.1.1", "77.88.8.8", "9.9.9.9", "208.67.222.222"],
            "services": {
                "Google": "8.8.8.8",
                "Cloudflare": "1.1.1.1",
                "Яндекс": "77.88.8.8",
                "VK": "vk.com",
                "YouTube": "youtube.com"
            }
        },
        "security": {
            "suspicious_ports": [4444, 1337, 31337, 6667, 4443, 8080, 8888, 3389, 5900, 22, 23]
        }
    }
    
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r', encoding='utf-8') as f:
                saved_config = json.load(f)
                config = default_config.copy()
                for key, value in saved_config.items():
                    if key in config and isinstance(config[key], dict) and isinstance(value, dict):
                        config[key].update(value)
                    else:
                        config[key] = value
                logger.info(f"Конфигурация загружена из {config_file}")
                return config
    except Exception as e:
        logger.error(f"Ошибка загрузки конфига: {e}")
    
    logger.info("Используется конфигурация по умолчанию")
    return default_config

# Аварийное сохранение
def emergency_save(app=None):
    try:
        logger.warning("Аварийное сохранение данных...")
        if app:
            if hasattr(app, 'sniffer'):
                app.sniffer._save_traffic_to_db()
            if hasattr(app, 'pinger'):
                app.pinger._flush_saves()
            if hasattr(app, 'ai_orchestrator'):
                app.ai_orchestrator.stop()
    except Exception as e:
        logger.error(f"Ошибка аварийного сохранения: {e}")

atexit.register(lambda: emergency_save(None))

def main():
    """Главная функция"""
    logger.info("=" * 50)
    logger.info("Запуск Network Monitor Pro v7.0 - AI Enterprise Edition")
    logger.info("=" * 50)
    
    try:
        # Загрузка конфига
        config = load_config()
        
        # Инициализация компонентов
        db_manager = DatabaseManager()
        
        # Создание Sniffer с callback для БД
        sniffer = Sniffer()
        sniffer.set_db_callback(
            lambda speed, bytes_in, bytes_out, bytes_in_delta, bytes_out_delta:
            db_manager.execute(
                """INSERT INTO traffic 
                   (timestamp, speed, bytes_in, bytes_out, bytes_in_delta, bytes_out_delta) 
                   VALUES (?,?,?,?,?,?)""",
                (
                    datetime.now().isoformat(),
                    speed,
                    bytes_in,
                    bytes_out,
                    bytes_in_delta,
                    bytes_out_delta
                )
            )
        )
        
        # Создание Pinger с callback для БД
        pinger = Pinger(config.get("ping_target", "8.8.8.8"))
        pinger.set_db_callback(
            lambda saves: db_manager.execute_many(
                """INSERT INTO pings 
                   (timestamp, ping_ms, loss, jitter, target) 
                   VALUES (?,?,?,?,?)""",
                [(s['timestamp'], s['ping_ms'], s['loss'], s['jitter'], s['target']) 
                 for s in saves]
            )
        )
        
        # Создание AI Orchestrator
        ai_orchestrator = AIOrchestrator(
            config=config.get("ai", {}),
            db_callback=db_manager.execute,
            alert_callback=lambda data: logger.warning(f"AI Alert: {data}")
        )
        
        # Инициализация Synapse
        if config.get("ai", {}).get("enabled", True):
            ai_orchestrator.initialize_synapse()
            ai_orchestrator.start_background_training()
            
            # Обучение на исторических данных
            try:
                data = db_manager.execute(
                    """SELECT speed, bytes_in_delta, bytes_out_delta, ping_ms
                    FROM traffic t
                    LEFT JOIN pings p ON date(t.timestamp) = date(p.timestamp)
                    ORDER BY t.timestamp DESC 
                    LIMIT 1000""",
                    fetch=True
                )
                
                if data and len(data) > 10:
                    historical = [
                        {
                            "speed": row['speed'],
                            "bytes_in": row['bytes_in_delta'],
                            "ping_ms": row.get('ping_ms', 0)
                        }
                        for row in data
                    ]
                    ai_orchestrator.train_model(historical)
                    logger.info("AI модель обучена на исторических данных")
            except Exception as e:
                logger.error(f"Ошибка обучения AI: {e}")
        
        # Создание главного окна
        app = App(db_manager, sniffer, pinger, ai_orchestrator, config)
        
        # Сохраняем ссылку для аварийного сохранения
        global _app
        _app = app
        atexit.register(lambda: emergency_save(_app))
        
        # Запуск
        app.run()
        
    except KeyboardInterrupt:
        logger.info("Приложение остановлено пользователем")
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        input("Нажмите Enter для выхода...")
        sys.exit(1)

if __name__ == "__main__":
    main()