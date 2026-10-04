"""Системные утилиты NetPulse (v3-реализация, поведение 1:1 с legacy).

- FirewallCtl — управление Windows Firewall через netsh.
- BackupManager — автобэкапы исходников (WinRAR → fallback zip).
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import threading
import uuid
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.utils import decode_process_output

logger = logging.getLogger(__name__)


class FirewallCtl:
    """Статические операции с Windows Firewall (правила NetPulse_*)."""

    RULE_PREFIX = "NetPulse_"

    @staticmethod
    def admin_ok() -> bool:
        """Права администратора (нужны для изменения правил firewall)."""
        if sys.platform != "win32":
            return False
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @staticmethod
    def _run(args: List[str], timeout: int = 10) -> Tuple[bool, str]:
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall"] + args,
            capture_output=True, timeout=timeout, creationflags=flags,
        )
        out = decode_process_output(result.stdout + result.stderr)
        lowered = out.lower()
        ok = result.returncode == 0 and (
            "Ok." in out
            or "ОК" in out
            or "обновлено" in lowered
            or "Updated" in out
            or "added" in lowered
            or "удалено" in lowered
            or "deleted" in lowered
        )
        return ok, out.strip()[:200]

    @classmethod
    def block_ip(cls, ip: str, direction: str = "both") -> Dict[str, Any]:
        name = f"{cls.RULE_PREFIX}IP_{ip.replace(':', '_')}"
        dirs = ["in", "out"] if direction == "both" else [direction]
        results = []
        for d in dirs:
            ok, _msg = cls._run(["add", "rule", f"name={name}_{d}",
                                 f"dir={d}", "action=block", f"remoteip={ip}"])
            results.append({"dir": d, "ok": ok})
        return {"ok": all(x["ok"] for x in results), "results": results}

    @classmethod
    def block_app(cls, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            return {"ok": False, "error": "файл не найден"}
        name = f"{cls.RULE_PREFIX}APP_{uuid.uuid4().hex[:6]}"
        results = []
        for d in ("in", "out"):
            ok, _msg = cls._run(["add", "rule", f"name={name}_{d}",
                                 f"dir={d}", "action=block",
                                 f"program={path}", "enable=yes"])
            results.append(ok)
        return {"ok": all(results), "name": name}

    @classmethod
    def unblock(cls, rule_name: str) -> Dict[str, Any]:
        ok, _msg = cls._run(["delete", "rule", f"name={rule_name}"])
        return {"ok": ok}

    @classmethod
    def list_rules(cls) -> Dict[str, Any]:
        """Правила с префиксом NetPulse_ (парсинг RU/EN вывода netsh)."""
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show",
                 "rule", "name=all", "dir=out"],
                capture_output=True, timeout=15, creationflags=flags,
            )
            return {"rules": cls.parse_rules(decode_process_output(result.stdout))}
        except Exception as e:
            return {"rules": [], "error": str(e)}

    @classmethod
    def parse_rules(cls, text: str) -> List[Dict[str, Any]]:
        """Чистая функция парсинга (тестируемая без netsh)."""
        rules: List[Dict[str, Any]] = []
        current: Dict[str, Any] = {}
        for line in text.splitlines():
            line = line.strip()
            m = re.match(r"^Имя правила:\s+(.+)$|^Rule Name:\s+(.+)$", line)
            if m:
                if current.get("name", "").startswith(cls.RULE_PREFIX):
                    rules.append(current)
                current = {"name": m.group(1) or m.group(2)}
            elif current is not None:
                m2 = re.match(r"^(?:Включено|Enabled):\s+(\S+)", line)
                if m2:
                    current["enabled"] = m2.group(1)
                m3 = re.match(r"^(?:Удаленный IP-адрес|RemoteIP):\s+(\S+)", line)
                if m3:
                    current["remoteip"] = m3.group(1)
                m4 = re.match(r"^(?:Программа|Program):\s+(.+)$", line)
                if m4:
                    current["program"] = m4.group(1).strip()
        if current.get("name", "").startswith(cls.RULE_PREFIX):
            rules.append(current)
        return rules


class BackupManager:
    """Автобэкапы исходников по расписанию + ручной запуск."""

    RAR_PATHS = ("C:\\Program Files\\WinRAR\\Rar.exe",
                 "C:\\Program Files (x86)\\WinRAR\\Rar.exe")
    EXCLUDE_DIRS = {"__pycache__", ".git"}
    EXCLUDE_SUFFIXES = (".db-wal", ".db-shm")

    def __init__(self, config: Dict[str, Any], source_dir: Optional[str] = None):
        self.cfg = config
        self._stop = threading.Event()
        self._source_dir = source_dir or os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True, name="np-backup").start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.run_backup_if_due()
            self._stop.wait(600)

    @classmethod
    def _find_rar(cls) -> Optional[str]:
        for path in cls.RAR_PATHS:
            if os.path.exists(path):
                return path
        return None

    def _stamp_file(self) -> str:
        backup_cfg = self.cfg.get("backup", {})
        return os.path.join(backup_cfg.get("dir", "C:\\Backups"), ".last_auto_run")

    def run_backup_if_due(self) -> None:
        backup_cfg = self.cfg.get("backup", {})
        if not (backup_cfg.get("enabled") and backup_cfg.get("time")):
            return
        now = datetime.now().strftime("%H:%M")
        stamp_file = self._stamp_file()
        target_time = backup_cfg["time"]
        today_stamp = datetime.now().strftime("%Y%m%d")
        try:
            if now >= target_time and (
                not os.path.exists(stamp_file)
                or open(stamp_file).read().strip() != today_stamp
            ):
                self.run_backup_now()
                os.makedirs(os.path.dirname(stamp_file), exist_ok=True)
                with open(stamp_file, "w") as f:
                    f.write(today_stamp)
                self.rotate(int(backup_cfg.get("keep", 7)))
        except Exception as e:
            logger.info(f"[backup] {e}")

    def run_backup_now(self, rar: Optional[str] = None) -> Dict[str, Any]:
        """Бэкап исходников: WinRAR, если установлен, иначе zip из stdlib."""
        backup_cfg = self.cfg.get("backup", {})
        dest_dir = backup_cfg.get("dir", "C:\\Backups")
        os.makedirs(dest_dir, exist_ok=True)
        src = self._source_dir
        stamp = f"{datetime.now():%Y%m%d_%H%M}"

        rar = rar if rar is not None else self._find_rar()
        if rar:
            dest = os.path.join(dest_dir, f"netpulse_auto_{stamp}.rar")
            cmd = [rar, "a", "-r", "-ep1", "-y", "-m5",
                   "-x*.db-wal", "-x*.db-shm",
                   "-x*\\__pycache__\\*", "-x*\\__pycache__",
                   dest, src]
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=300,
                                        creationflags=flags)
                if result.returncode == 0:
                    return {"ok": True, "archive": dest}
                logger.info(f"[backup] rar завершился с кодом {result.returncode}, fallback на zip")
            except Exception as e:
                logger.warning(f"[backup] rar недоступен ({e}), fallback на zip")

        dest = os.path.join(dest_dir, f"netpulse_auto_{stamp}.zip")
        try:
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as archive:
                for root, dirs, files in os.walk(src):
                    dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]
                    for name in files:
                        if name.endswith(self.EXCLUDE_SUFFIXES):
                            continue
                        full = os.path.join(root, name)
                        if full == dest:
                            continue
                        archive.write(full, os.path.relpath(full, src))
            return {"ok": True, "archive": dest}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def rotate(self, keep: int = 7) -> None:
        dest_dir = self.cfg.get("backup", {}).get("dir", "C:\\Backups")
        try:
            archives = sorted(
                (f for f in os.listdir(dest_dir) if f.startswith("netpulse_auto_")),
                reverse=True)
            for old in archives[keep:]:
                os.remove(os.path.join(dest_dir, old))
        except Exception:
            pass
