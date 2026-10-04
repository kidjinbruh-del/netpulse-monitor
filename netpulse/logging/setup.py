import logging
import logging.handlers
import sys
from pathlib import Path

from netpulse.config import Config
from .formatters import JsonFormatter, HumanFormatter


def setup_logging(log_config: Config) -> logging.Logger:
    """
    Настраивает логирование согласно конфигурации.
    Возвращает корневой логгер netpulse.
    """
    # Определяем уровень
    level = getattr(logging, log_config.level.upper(), logging.INFO)
    
    # Корневой логгер
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Очищаем существующие хендлеры
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Консольный хендлер (human-readable)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(HumanFormatter())
    root_logger.addHandler(console_handler)
    
    # Файловый хендлер с ротацией (JSON)
    log_path = Path(log_config.file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    file_handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=log_config.max_bytes,
        backupCount=log_config.backup_count,
        encoding="utf-8"
    )
    file_handler.setLevel(level)
    if log_config.json_format:
        file_handler.setFormatter(JsonFormatter(include_extra=True))
    else:
        file_handler.setFormatter(HumanFormatter())
    root_logger.addHandler(file_handler)
    
    # Настраиваем логгер netpulse
    netpulse_logger = logging.getLogger("netpulse")
    netpulse_logger.setLevel(level)
    netpulse_logger.propagate = True  # Пропускаем к root logger
    
    # Отключаем шумные сторонние логгеры
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    
    return netpulse_logger


def get_logger(name: str) -> logging.Logger:
    """Получить логгер для модуля netpulse."""
    return logging.getLogger(f"netpulse.{name}")