from pathlib import Path
from typing import Any, Dict, Optional
import json

from .defaults import Config, DEFAULTS_DICT, PROTECTED_SETTINGS, load_config_dict, merge_configs, save_config
from .legacy_adapter import adapt_legacy


class ConfigLoader:
    def __init__(self, config_path: str = "config.json"):
        self.config_path = Path(config_path).resolve()
        self._config: Optional[Config] = None
    
    def load(self) -> Config:
        file_config = load_config_dict(str(self.config_path))
        # DPAPI: расшифровываем dpapi:-значения в память (как legacy load_config).
        # В файл пишется только зашифрованное (через legacy save_config).
        try:
            from core.secrets import decrypt_config
            file_config = decrypt_config(file_config)
        except Exception:
            pass
        adapted = adapt_legacy(file_config)
        adapted.pop("_legacy", None)
        # Сохраняем сырой legacy-словарь для to_legacy_dict().
        adapted["legacy_raw"] = file_config
        # Недостающие секции подставятся дефолтами вложенных моделей.
        self._config = Config(**adapted)
        return self._config
    
    def save(self, config: Optional[Config] = None) -> None:
        cfg = config or self._config
        if cfg is None:
            raise RuntimeError("No config to save")
        save_config(cfg.model_dump(mode="json"), str(self.config_path))
    
    def update(self, updates: Dict[str, Any], protect: bool = True) -> Config:
        if self._config is None:
            self.load()
        current = self._config.model_dump(mode="json")
        
        if protect:
            for key in PROTECTED_SETTINGS:
                updates.pop(key, None)
        
        merged = merge_configs(current, updates)
        self._config = Config(**merged)
        return self._config
    
    @property
    def config(self) -> Config:
        if self._config is None:
            return self.load()
        return self._config


def load_config(config_path: str = "config.json") -> Config:
    loader = ConfigLoader(config_path)
    return loader.load()