"""Адаптер legacy config.json (v2, плоские + вложенные ключи)
в новую вложенную структуру Config (v3).

Неизвестные секции/поля игнорируются Pydantic (extra="ignore").
"""
from typing import Any, Dict


FLAT_MAP = {
    "web_host": ("web", "host"),
    "web_port": ("web", "port"),
    "web_auth_enabled": ("web", "auth_enabled"),
    "web_token": ("web", "token"),
    "web_admins": ("web", "admins"),
    "web_users": ("web", "users"),
    "ping_interval_sec": ("ping", "interval_sec"),
    "ping_target": ("ping", "targets"),
}


def _ensure_section(out: Dict[str, Any], name: str) -> Dict[str, Any]:
    section = out.get(name)
    if not isinstance(section, dict):
        section = {}
        out[name] = section
    return section


def adapt_legacy(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Преобразовать legacy-словарь в структуру v3. Возвращает новый dict."""
    out: Dict[str, Any] = {}
    leftovers: Dict[str, Any] = {}

    for key, value in raw.items():
        if key in FLAT_MAP:
            section_name, field = FLAT_MAP[key]
            section = _ensure_section(out, section_name)
            if key == "ping_target" and isinstance(value, str):
                value = [value]
            section[field] = value
        elif key == "web_tls" and isinstance(value, dict):
            section = _ensure_section(out, "web")
            if "enabled" in value:
                section["tls_enabled"] = value["enabled"]
            if "cert" in value:
                section["tls_cert"] = value["cert"]
            if "key" in value:
                section["tls_key"] = value["key"]
        elif key == "p2p" and isinstance(value, dict):
            section = _ensure_section(out, "p2p")
            section.update(value)
        elif key == "mtr" and isinstance(value, dict):
            section = _ensure_section(out, "mtr")
            section.update(value)
            target = value.get("target")
            if target and not section.get("targets"):
                section["targets"] = [target]
        elif key == "speedtest" and isinstance(value, dict):
            section = _ensure_section(out, "speedtest")
            section.update(value)
            if "bytes" in value and "bytes_down" not in section:
                section["bytes_down"] = value["bytes"]
        elif isinstance(value, dict):
            # Остальные вложенные секции (ai, backup, ids, ...) — как есть,
            # лишние поля отсечёт Pydantic (extra="ignore").
            merged = _ensure_section(out, key)
            merged.update(value)
        else:
            leftovers[key] = value

    # Неизвестные плоские ключи (theme, email, lan, ...) — сохраняем как есть,
    # Pydantic их проигнорирует, но они останутся доступны через leftovers.
    out["_legacy"] = leftovers
    return out
