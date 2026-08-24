"""
NetPulse — десктопная версия (CustomTkinter UI).
Точка входа в приложение
"""

import sys
import os
import json
import copy
import atexit
import logging
import logging.handlers
from datetime import datetime

# Корень проекта в sys.path для абсолютных импортов core/ai/ui
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui import App
from ai import AIOrchestrator
from core import DatabaseManager, Sniffer, Pinger


def setup_logging():
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, f"network_monitor_{datetime.now().strftime('%Y%m%d')}.log")

    rotating = logging.handlers.RotatingFileHandler(
        log_file, encoding='utf-8', maxBytes=2 * 1024 * 1024, backupCount=5
    )

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            rotating,
            logging.StreamHandler()
        ]
    )

    return logging.getLogger("main")


logger = setup_logging()

# ========== КОНФИГ ==========
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
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
        "history_window": 1000,
        "features": ["speed", "bytes_in", "bytes_out", "ping_ms", "jitter"],
        "synapse_enabled": False,
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


def load_config():
    """Загрузка конфига с глубоким слиянием (без мутации дефолтов)"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                saved_config = json.load(f)
                config = copy.deepcopy(DEFAULT_CONFIG)
                for key, value in saved_config.items():
                    if key in config and isinstance(config[key], dict) and isinstance(value, dict):
                        config[key].update(value)
                    else:
                        config[key] = value
                logger.info(f"Конфигурация загружена из {CONFIG_FILE}")
                return config
    except Exception as e:
        logger.error(f"Ошибка загрузки конфига: {e}")

    logger.info("Используется конфигурация по умолчанию")
    return copy.deepcopy(DEFAULT_CONFIG)


# Аварийное сохранение при неожиданном завершении
_app_ref = None


def emergency_save():
    try:
        app = _app_ref
        if app is None:
            return
        logger.warning("Выполняется аварийное сохранение данных...")
        if hasattr(app, 'sniffer') and app.sniffer:
            try:
                app.sniffer._save_traffic_to_db()
            except Exception:
                pass
        if hasattr(app, 'pinger') and app.pinger:
            try:
                app.pinger._flush_saves()
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Ошибка аварийного сохранения: {e}")


def make_training_data_provider(db_manager):
    """Провайдер свежих данных для фонового обучения AI"""
    def provider():
        traffic = db_manager.execute(
            """SELECT timestamp, speed, bytes_in_delta AS bytes_in
               FROM traffic
               WHERE speed IS NOT NULL AND timestamp > datetime('now', 'localtime', '-2 hours')
               ORDER BY timestamp DESC LIMIT 500""",
            fetch=True
        ) or []

        pings = db_manager.execute(
            """SELECT timestamp, ping_ms, jitter
               FROM pings
               WHERE ping_ms IS NOT NULL AND timestamp > datetime('now', 'localtime', '-2 hours')
               ORDER BY timestamp DESC LIMIT 500""",
            fetch=True
        ) or []

        # Сопоставление по ближайшему timestamps (обе выборки отсортированы)
        ping_by_ts = {p['timestamp'][:19]: p for p in pings}
        data = []
        for row in traffic:
            ts_key = row['timestamp'][:19]
            ping = ping_by_ts.get(ts_key, {})
            data.append({
                "speed": row['speed'],
                "bytes_in": row['bytes_in'],
                "bytes_out": 0,
                "ping_ms": ping.get('ping_ms', 0) or 0,
                "jitter": ping.get('jitter', 0) or 0,
            })
        return data
    return provider


def main():
    global _app_ref

    logger.info("=" * 50)
    logger.info("Запуск NetPulse (десктопная версия)")
    logger.info("=" * 50)

    db_manager = None
    sniffer = None
    pinger = None

    try:
        config = load_config()
        ai_enabled = config.get("ai", {}).get("enabled", True)

        # БД
        db_manager = DatabaseManager()

        # Сниффер трафика
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

        # Пингер (+алерты в БД)
        def save_alert(alert_type, message):
            db_manager.execute(
                """INSERT INTO alerts 
                   (timestamp, alert_type, message, source) 
                   VALUES (?,?,?,?)""",
                (datetime.now().isoformat(), alert_type, message, "pinger")
            )

        pinger = Pinger(
            target=config.get("ping_target", "8.8.8.8"),
            alert_thresholds=config.get("alert_thresholds", {}),
            alert_callback=save_alert
        )
        pinger.set_db_callback(
            lambda saves: db_manager.execute_many(
                """INSERT INTO pings 
                   (timestamp, ping_ms, loss, jitter, target) 
                   VALUES (?,?,?,?,?)""",
                [(s['timestamp'], s['ping_ms'], s['loss'], s['jitter'], s['target'])
                 for s in saves]
            )
        )

        # AI оркестратор
        ai_orchestrator = None
        if ai_enabled:
            ai_orchestrator = AIOrchestrator(
                config=config.get("ai", {}),
                alert_callback=lambda data: logger.warning(f"AI Alert: {data}"),
                data_provider=make_training_data_provider(db_manager)
            )

            if ai_orchestrator.initialize_synapse():
                logger.info("Synapse агент инициализирован")
            ai_orchestrator.start_background_training()

            # Первичное обучение на исторических данных
            try:
                historical = make_training_data_provider(db_manager)()
                if historical and len(historical) >= 10:
                    if ai_orchestrator.train_model(historical):
                        logger.info(f"AI модель обучена на {len(historical)} записях истории")
            except Exception as e:
                logger.error(f"Ошибка обучения AI: {e}")

        # Главное окно
        app = App(db_manager, sniffer, pinger, ai_orchestrator, config)
        _app_ref = app
        atexit.register(emergency_save)

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
