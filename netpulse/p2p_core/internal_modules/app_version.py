# src/internal_modules/app_version.py
# Версия приложения: чтение version.txt (в frozen — из бандла), парсинг
# и сравнение формата MAJOR.MINOR.PATCH[-buildN].

import re
import sys
from functools import lru_cache
from pathlib import Path

DEV_VERSION = '0.0.0-dev'

_VERSION_RE = re.compile(r'^\s*v?(\d+)\.(\d+)\.(\d+)(?:-build(\d+))?\s*$')


def parse_version(s: str):
    """'2.1.0' / 'v2.1.0-build42' → (2, 1, 0, 42); None если не разобрать."""
    m = _VERSION_RE.match(s or '')
    if not m:
        return None
    maj, mi, pat, build = m.groups()
    return (int(maj), int(mi), int(pat), int(build or 0))


def compare_versions(a: str, b: str) -> int:
    """-1 a<b, 0 равны, +1 a>b. Неразбираемые — лексикографически."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        sa, sb = (a or '').lower(), (b or '').lower()
        return (sa > sb) - (sa < sb)
    return (pa > pb) - (pa < pb)


def is_newer(candidate: str, current: str) -> bool:
    """candidate строго новее current (неразбираемый candidate → False)."""
    c = parse_version(candidate)
    if c is None:
        return False
    cur = parse_version(current)
    if cur is None:
        return True
    return c > cur


def candidate_paths() -> list:
    out = []
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            out.append(Path(meipass) / 'version.txt')
        out.append(Path(sys.executable).parent / 'version.txt')
    else:
        # dev-запуск: корень проекта = родители src/internal_modules/*
        out.append(Path(__file__).resolve().parents[2] / 'version.txt')
    return out


@lru_cache(maxsize=1)
def read_version() -> str:
    """Текущая версия узла; '0.0.0-dev' если version.txt не найден."""
    for p in candidate_paths():
        try:
            if p.is_file():
                txt = p.read_text(encoding='utf-8').strip()
                if txt:
                    return txt
        except OSError:
            continue
    return DEV_VERSION
