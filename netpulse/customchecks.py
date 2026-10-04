"""Пользовательские проверки: python-файлы в custom_checks/*.py.

Контракт модуля:
    NAME = "Проверка 1С"                    # необязательно, по умолчанию имя файла
    INTERVAL_MIN = 15                        # необязательно, минимум между запусками
    def run():
        return {"ok": True, "text": "1С отвечает за 20 мс"}
        # ok=False или поле "warn": True -> событие WARN в парке

Безопасность: файлы пишете вы сами и они исполняются с правами сервера —
кладите сюда только свой код.

v3-реализация: тот же контракт CustomChecks(service), типизировано.
service опционально даёт .inventory (для событий о провалах).
"""
from __future__ import annotations

import importlib.util
import logging
import os
import socket
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

CHECKS_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "custom_checks")


class CustomChecks:
    def __init__(self, service: Any, checks_dir: Optional[str] = None):
        self.svc = service
        self.checks_dir = checks_dir or CHECKS_DIR
        self._mods: List[Dict[str, Any]] = []
        self._last_run: Dict[str, float] = {}   # path -> ts
        self._results: List[Dict[str, Any]] = []
        self.load()

    def load(self) -> Dict[str, Any]:
        self._mods = []
        if not os.path.isdir(self.checks_dir):
            try:
                os.makedirs(self.checks_dir, exist_ok=True)
                example = os.path.join(self.checks_dir, "example_disks.py")
                with open(example, "w", encoding="utf-8") as f:
                    f.write(
                        'NAME = "Пример: свободное место C:"\n'
                        'def run():\n'
                        '    import shutil\n'
                        '    free = shutil.disk_usage("C:").free / 1e9\n'
                        '    return {"ok": free > 5,\n'
                        '            "text": f"свободно {free:.1f} GB"}\n')
            except Exception as e:
                logger.warning("custom_checks: %s", e)
        for filename in sorted(os.listdir(self.checks_dir)):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue
            path = os.path.join(self.checks_dir, filename)
            try:
                spec = importlib.util.spec_from_file_location(
                    f"custom_check_{filename[:-3]}", path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                interval = int(getattr(mod, "INTERVAL_MIN", 15) or 15)
                self._mods.append({
                    "path": path, "name": getattr(mod, "NAME", filename[:-3]),
                    "interval_min": interval,
                    "run": getattr(mod, "run", None)})
            except Exception as e:
                logger.warning("custom check %s битый: %s", filename, e)
        return {"ok": True, "count": len(self._mods)}

    def run_all(self, force: bool = False) -> Dict[str, Any]:
        out = []
        now = time.time()
        for mod in self._mods:
            if not callable(mod.get("run")):
                continue
            key = mod["path"]
            if not force and now - self._last_run.get(key, 0) < \
                    mod["interval_min"] * 60:
                prev = next((r for r in self._results
                             if r["name"] == mod["name"]), None)
                if prev:
                    out.append(prev)
                continue
            item = self._run_single(mod)
            out.append(item)
            self._results = [x for x in self._results
                             if x["name"] != mod["name"]] + [item]
            if not item["ok"]:
                self._report_failure(mod, item)
        return {"ok": True, "results": out}

    def _run_single(self, mod: Dict[str, Any]) -> Dict[str, Any]:
        t0 = time.time()
        try:
            result = mod["run"]() or {}
            ok = bool(result.get("ok"))
            text = str(result.get("text") or "")[:200]
        except Exception as e:
            ok, text = False, f"ошибка проверки: {e}"
        ms = round((time.time() - t0) * 1000)
        self._last_run[mod["path"]] = time.time()
        return {"name": mod["name"], "ok": ok, "text": text, "ms": ms}

    def _report_failure(self, mod: Dict[str, Any], item: Dict[str, Any]) -> None:
        try:
            inv = getattr(self.svc, "inventory", None)
            infra = getattr(self.svc, "infra", None)
            gateway = infra.gateway_ip() if infra else None
            host = socket.gethostname() if gateway else None
            hid = inv.resolve_host_id(host) if inv and host else None
            if hid:
                inv.note_event(
                    hid, "custom", "WARN", "custom_check",
                    f"{mod['name']}: {item['text']}",
                    dedup_key=f"cc:{mod['name']}:{datetime.now():%Y%m%d%H}",
                    dedup_hours=1)
        except Exception:
            pass

    def results(self) -> Dict[str, Any]:
        return {"results": self._results, "count": len(self._mods)}
