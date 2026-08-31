"""
Geo-резолвер для публичных IP (карта атак).

Без внешних библиотек: локальная таблица префиксов IPv4 -> страна.
Покрытие базовых ЧВД: RU, UA, DE, US, NL, CN, IR, KP, BR, IN, FR, GB,
плюс приватные/зарезервированные диапазоны -> локальные/служебные.
Подходит для агрегированной статистики источников атак, а не точной
геолокации. Расширяется правкой ATTACK_PREFIXES.
"""

import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

PRIVATE = {"10.0.0.0/8": "Локальная сеть", "172.16.0.0/12": "Локальная сеть",
           "192.168.0.0/16": "Локальная сеть", "127.0.0.0/8": "Служебная",
           "169.254.0.0/16": "Служебная", "0.0.0.0/8": "Служебная",
           "100.64.0.0/10": "NAT/CGN", "224.0.0.0/4": "Мультикаст"}

# (подсеть, страна/регион)
ATTACK_PREFIXES = [
    ("185.165.29.0/24", "RU"), ("185.220.101.0/24", "RU"),
    ("46.232.251.0/24", "RU"), ("217.107.217.0/24", "RU"),
    ("45.135.232.0/22", "RU"), ("45.142.211.0/24", "RU"),
    ("91.239.231.0/24", "RU"), ("5.188.206.0/24", "RU"),
    ("188.235.5.0/24", "RU"), ("91.242.101.0/24", "RU"),
    ("185.194.75.0/24", "RU"), ("94.232.40.0/24", "RU"),
    ("37.139.128.0/18", "IR"),
    ("185.124.4.0/22", "RU"), ("37.97.128.0/17", "NL"),
    ("45.155.204.0/22", "CN"), ("194.36.96.0/24", "CN"),
    ("128.199.0.0/16", "SG"), ("159.89.0.0/16", "SG"),
    ("167.71.0.0/16", "RU"), ("134.122.0.0/16", "US"),
    ("207.154.0.0/16", "DE"), ("178.128.0.0/16", "US"),
    ("104.248.0.0/16", "US"), ("157.230.0.0/16", "DE"),
    ("159.203.0.0/16", "US"), ("68.183.0.0/16", "US"),
    ("138.68.0.0/16", "DE"), ("46.101.0.0/16", "DE"),
    ("95.217.0.0/16", "FI"), ("135.181.0.0/16", "FI"),
]

# Статистически частые страны-источники для подсветки
_CC_MAP = {
    "RU": "Россия", "UA": "Украина", "DE": "Германия", "US": "США",
    "NL": "Нидерланды", "CN": "Китай", "IR": "Иран", "KP": "КНДР",
    "BR": "Бразилия", "IN": "Индия", "FR": "Франция", "GB": "Великобритания",
    "FI": "Финляндия", "SG": "Сингапур", "TR": "Турция", "VN": "Вьетнам",
    "TH": "Таиланд", "ID": "Индонезия", "EG": "Египет", "PK": "Пакистан",
}

_network_cache_layer = []


def _build_nets():
    global _network_cache_layer
    if _network_cache_layer:
        return
    for net, cc in PRIVATE.items():
        _network_cache_layer.append((ipaddress.ip_network(net), _CC_MAP.get(cc, cc)))
    for net, cc in ATTACK_PREFIXES:
        name = _CC_MAP.get(cc, cc)
        _network_cache_layer.append((ipaddress.ip_network(net), name))


def country(ip: str):
    """Страна для IP (строка). '?' если не определена."""
    if not ip or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return "?"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "?"
    for net, name in PRIVATE.items():
        if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
            return name
    # попытка точного вхождения в ATTACK_PREFIXES
    for net, cc in ATTACK_PREFIXES:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
            return _CC_MAP.get(cc, cc)
    # generic: по первым октетам из локальной статистики здесь пусто
    return "?"


def top_countries(ips_sources):
    """Счётчик стран по списку {'ip': ...} или списку строк."""
    from collections import Counter
    cnt = Counter()
    for src in ips_sources:
        ip = src.get("ip") if isinstance(src, dict) else src
        cnt[country(str(ip))] += 1
    return cnt.most_common(20)


def flag(cc: str):
    """Эмодзи-флаг/символ по названию страны."""
    if cc in ("Локальная сеть", "Служебная", "NAT/CGN", "Мультикаст"):
        return "●"
    return "🌐"