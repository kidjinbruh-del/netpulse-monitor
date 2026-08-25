"""
Конфигурация NetPulse (config.json, глубокое слияние с дефолтами)
"""

import json
import copy
import os
import uuid
from datetime import datetime

from core.secrets import encrypt_config, decrypt_config
import logging

logger = logging.getLogger(__name__)
CONFIG_FILE = "config.json"

DEFAULTS = {
    "web_port": 8770,
    "web_host": "127.0.0.1",
    "web_auth_enabled": False,
    "web_token": "",
    "web_admins": [],
    "theme": "dark",
    "ping_interval_sec": 1,
    "db_cleanup_days": 30,
    "ping_target": "8.8.8.8",
    "quality": {
        "good_ping_ms": 50,
        "warn_ping_ms": 120,
        "max_jitter_ms": 15,
        "max_loss_pct": 2
    },
    "quota": {
        "daily_mb": 0,      # 0 = без лимита
        "monthly_gb": 0,
        "warn_pct": 80
    },
    "ai": {
        "enabled": True,
        "anomaly_threshold": 0.6,
        "training_interval": 300,
        "features": ["speed", "bytes_in", "bytes_out", "ping_ms", "jitter"]
    },
    "security": {
        "suspicious_ports": [4444, 1337, 31337, 6667, 4443, 8080, 8888, 3389, 5900, 22, 23],
        "scan_detection_threshold": 15   # разных портов с одного IP за окно -> IDS алерт
    },
    "ids": {
        "enabled": True,
        "window_sec": 120,
        "whitelist": []
    },
    "infra": {
        "community": "public"
    },
    "lan": {
        "auto_scan_min": 10
    },
    "diagnostics": {
        "trace_targets": ["8.8.8.8", "1.1.1.1", "77.88.8.8"],
        "resolve_hosts": ["google.com", "youtube.com", "vk.com", "github.com", "wikipedia.org"]
    },
    "mtr": {
        "target": "8.8.8.8",
        "max_hops": 12,
        "cycle_sec": 10,
        "pings_per_hop": 2
    },
    "speedtest": {
        "url_down": "https://speed.cloudflare.com/__down?bytes={bytes}",
        "url_up": "https://speed.cloudflare.com/__up",
        "bytes": 8000000,
        "timeout_sec": 20
    },
    "webhook": {
        "enabled": False,
        "url": ""
    },
    "healing": {
        "enabled": False,
        "rules": []
    },
    "email": {
        "enabled": False,
        "smtp_host": "",
        "smtp_port": 25,
        "use_tls": True,
        "user": "",
        "password": "",
        "from": "netpulse@localhost",
        "to": ""
    },
    "healing": {
        "enabled": False,
        "rules": []
    },
    "telegram": {
        "enabled": False,
        "token": "",
        "chat_id": ""
    },
    "backup": {
        "enabled": False,
        "time": "03:00",
        "keep": 7,
        "dir": "C:\\Backups"
    },
    "journal": {
        "default_minutes": 0
    },
    "watchdog": {
        "enabled": False,
        "interval_min": 15,
        "timeout_sec": 25,
        "hosts": ["auto"],
        "disk_free_pct": 10,
        "ram_free_mb": 500,
        "event_ids": [41, 6008, 7, 153, 7031, 7034],
        "event_hours": 24,
        "offline_after_polls": 3
    },
    "runbooks": {
        "enabled": True
    },
    "backupwatch": {
        "enabled": False,
        "drill_reminder": True,
        "resources": []
    },
    "planner": {
        "enabled": False,
        "tasks": []
    },
    "web_tls": {
        "enabled": False,
        "cert": "netpulse/certs/cert.pem",
        "key": "netpulse/certs/key.pem"
    }
}


def _validate(cfg):
    """Мягкая валидация критичных полей: ошибка -> значение из DEFAULTS."""
    def reset(path):
        keys = path.split(".")
        node, src = cfg, DEFAULTS
        for k in keys[:-1]:
            node = node.setdefault(k, {})
            src = src.get(k, {})
        last = keys[-1]
        if last in src:
            node[last] = copy.deepcopy(src[last])
            print(f"[config] {path}: некорректное значение — использую default")

    def num_ok(v):
        return isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0

    if not num_ok(cfg.get("web_port")) or not (1 <= cfg["web_port"] <= 65535):
        reset("web_port")
    if not isinstance(cfg.get("web_host"), str):
        reset("web_host")
    numeric = {
        "watchdog": ("interval_min", "timeout_sec", "disk_free_pct",
                     "ram_free_mb", "event_hours", "offline_after_polls"),
        "mtr": ("max_hops", "cycle_sec", "pings_per_hop"),
        "quota": ("warn_pct",),
        "lan": ("auto_scan_min",),
        "ping_interval_sec": (),
        "db_cleanup_days": (),
    }
    for name, keys in numeric.items():
        if keys:
            sec = cfg.get(name)
            if not isinstance(sec, dict):
                cfg[name] = copy.deepcopy(DEFAULTS.get(name, {}))
                print(f"[config] {name}: секция восстановлена")
                continue
            for k in keys:
                if not num_ok(sec.get(k)):
                    reset(f"{name}.{k}")
        else:
            if not num_ok(cfg.get(name)):
                reset(name)
    return cfg


def load_config(path=CONFIG_FILE):
    cfg = copy.deepcopy(DEFAULTS)
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            _deep_merge(cfg, saved)
    except Exception as e:
        print(f"[config] ошибка загрузки: {e}")

    cfg = decrypt_config(cfg)   # dpapi: -> plaintext (в памяти только)
    cfg = _validate(cfg)

    if cfg.get("web_auth_enabled") and not cfg.get("web_token"):
        cfg["web_token"] = uuid.uuid4().hex
        save_config(cfg, path)
    return cfg


def _backup_config(path=CONFIG_FILE, keep=10):
    """Копия текущего конфига в backups/config/ перед перезаписью."""
    try:
        if not os.path.exists(path):
            return
        bdir = os.path.join("backups", "config")
        os.makedirs(bdir, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        import shutil
        shutil.copy2(path, os.path.join(bdir, f"config.backup_{ts}.json"))
        old = sorted(f for f in os.listdir(bdir)
                     if f.startswith("config.backup_"))
        for f in old[:-keep]:
            os.remove(os.path.join(bdir, f))
    except Exception as e:
        print(f"[config] бэкап не создан: {e}")


def save_config(cfg, path=CONFIG_FILE):
    try:
        _backup_config(path)
        stored = encrypt_config(copy.deepcopy(cfg))   # секреты -> dpapi:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(stored, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"[config] ошибка сохранения: {e}")
        return False


def merge_updates(cfg, updates):
    _deep_merge(cfg, updates or {})
    return cfg


def _deep_merge(base, extra):
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
