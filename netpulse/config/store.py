"""Файловое хранилище legacy-конфига (замена config_legacy.py).

Покрывает живой use-case: merge обновлений + сохранение config.json
с ротацией бэкапов и DPAPI-шифрованием секретов (используется
MonitorService.apply_settings через settings API).

Мёртвый код предшественника (load_config/DEFAULTS/_validate/_env_overrides)
не переносился — загрузка и валидация живут в loader.py + Pydantic-моделях.
"""
import copy
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict

logger = logging.getLogger(__name__)

CONFIG_FILE = "config.json"
BACKUP_KEEP = 10


def deep_merge(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    """Глубокое слияние extra в base (in-place, как legacy _deep_merge)."""
    for key, value in (extra or {}).items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def merge_updates(cfg: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    """Влить updates в cfg (in-place). Совместимо с legacy merge_updates."""
    return deep_merge(cfg, updates or {})


def backup_config(path: str = CONFIG_FILE, keep: int = BACKUP_KEEP) -> None:
    """Копия текущего конфига в backups/config/ перед перезаписью."""
    try:
        if not os.path.exists(path):
            return
        backup_dir = os.path.join(os.path.dirname(path) or ".", "backups", "config")
        os.makedirs(backup_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        import shutil
        shutil.copy2(path, os.path.join(backup_dir, f"config.backup_{stamp}.json"))
        old = sorted(f for f in os.listdir(backup_dir) if f.startswith("config.backup_"))
        for name in old[:-keep]:
            os.remove(os.path.join(backup_dir, name))
    except Exception as e:
        logger.warning(f"[config] бэкап не создан: {e}")


def save_legacy_config(cfg: Dict[str, Any], path: str = CONFIG_FILE) -> bool:
    """Сохранить legacy-dict: бэкап + DPAPI-шифрование секретов + запись."""
    try:
        from core.secrets import encrypt_config
        backup_config(path)
        stored = encrypt_config(copy.deepcopy(cfg))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(stored, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"[config] ошибка сохранения: {e}")
        return False


# Алиасы для drop-in замены config_legacy в legacy-потребителях.
save_config = save_legacy_config
