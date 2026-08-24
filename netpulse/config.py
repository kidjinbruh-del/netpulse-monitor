"""
Конфигурация NetPulse (config.json, глубокое слияние с дефолтами)
"""

import json
import copy
import os
import uuid

CONFIG_FILE = "config.json"

DEFAULTS = {
    "web_port": 8770,
    "web_auth_enabled": False,
    "web_token": "",
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
        "window_sec": 120
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
        "hosts": ["127.0.0.1"],
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
    }
}


def load_config(path=CONFIG_FILE):
    cfg = copy.deepcopy(DEFAULTS)
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            _deep_merge(cfg, saved)
    except Exception as e:
        print(f"[config] ошибка загрузки: {e}")

    if cfg.get("web_auth_enabled") and not cfg.get("web_token"):
        cfg["web_token"] = uuid.uuid4().hex
        save_config(cfg, path)
    return cfg


def save_config(cfg, path=CONFIG_FILE):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"[config] ошибка сохранения: {e}")
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
