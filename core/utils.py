"""
Утилиты для core модуля
"""

import subprocess
import sys
import os
import re
import json
import time
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def is_admin():
    """Проверка прав администратора (Windows)"""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def safe_kill_process(process, timeout=3):
    """Безопасное завершение процесса"""
    if not process:
        return
    
    try:
        process.terminate()
        try:
            process.wait(timeout=timeout)
            return
        except subprocess.TimeoutExpired:
            if sys.platform == "win32":
                try:
                    subprocess.run(
                        ['taskkill', '/F', '/T', '/PID', str(process.pid)],
                        capture_output=True,
                        timeout=timeout
                    )
                except:
                    process.kill()
            else:
                process.kill()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    logger.warning(f"Не удалось завершить процесс {process.pid}")
    except Exception as e:
        logger.error(f"Ошибка при завершении процесса: {e}")

def decode_process_output(data):
    """Декодирование вывода консольных утилит Windows (ping/netstat пишут в OEM-кодировке,
    а не в ANSI - наивный text=True ломает кириллицу и парсинг цифр не спасает regex'ы со словами)"""
    if isinstance(data, str):
        return data
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if sys.platform == "win32":
        try:
            return data.decode("cp866", "replace")
        except Exception:
            pass
    return data.decode("latin-1", "replace")


# Время в ответе ping: время=25мс / time<1ms / время = 25 мс (языконезависимо)
_MS_RE = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*(?:мс|ms)", re.IGNORECASE)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_ping_output(output):
    """Парсинг вывода ping: ищем число перед мс/ms. Нет числа -> потеря."""
    match = _MS_RE.search(output)
    if match:
        try:
            return float(match.group(1).replace(",", ".")), False
        except ValueError:
            return 0.0, True
    return 0.0, True


def parse_trace_output(output, target=None):
    """Парсинг хопа трассировки: первый IP, отличный от цели (заголовок содержит цель)."""
    candidates = _IP_RE.findall(output)
    ip = "*"
    for cand in candidates:
        if cand != target:
            ip = cand
            break
    else:
        if candidates:
            # Встретили только саму цель - маршрут достиг конца
            ip = candidates[-1]

    ms = 0.0
    match = _MS_RE.search(output)
    if match:
        try:
            ms = float(match.group(1).replace(",", "."))
        except ValueError:
            ms = 0.0
    return ip, ms

def emergency_cleanup(app=None):
    """Аварийное сохранение данных"""
    try:
        logger.warning("Выполняется аварийное сохранение данных...")
        if app:
            if hasattr(app, 'sniffer'):
                app.sniffer._save_traffic_to_db()
            if hasattr(app, 'pinger'):
                app.pinger._flush_saves()
            if hasattr(app, 'ai_orchestrator'):
                app.ai_orchestrator.stop()
    except Exception as e:
        logger.error(f"Ошибка аварийного сохранения: {e}")