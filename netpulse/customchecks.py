"""
Пользовательские проверки: python-файлы в custom_checks/*.py.

Контракт модуля:
    NAME = "Проверка 1С"                    # необязательно, по умолчанию имя файла
    INTERVAL_MIN = 15                        # необязательно, минимум между запусками
    def run():
        return {"ok": True, "text": "1С отвечает за 20 мс"}
        # ok=False или поле "warn": True -> событие WARN в парке

Безопасность: файлы пишете вы сами и они исполняются с правами сервера —
кладите сюда только свой код.
"""

import importlib.util
import logging
import os
import socket
import time
from datetime import datetime

logger = logging.getLogger(__name__)

CHECKS_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "custom_checks")


class CustomChecks:
    def __init__(self, service):
        self.svc = service
        self._mods = []
        self._last_run = {}   # path -> ts
        self._results = []
        self.load()

    def load(self):
        self._mods = []
        if not os.path.isdir(CHECKS_DIR):
            try:
                os.makedirs(CHECKS_DIR, exist_ok=True)
                example = os.path.join(CHECKS_DIR, "example_disks.py")
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
        for fn in sorted(os.listdir(CHECKS_DIR)):
            if not fn.endswith(".py") or fn.startswith("_"):
                continue
            path = os.path.join(CHECKS_DIR, fn)
            try:
                spec = importlib.util.spec_from_file_location(
                    f"custom_check_{fn[:-3]}", path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                self._mods.append({
                    "path": path, "name": getattr(mod, "NAME", fn[:-3]),
                    "interval_min": int(getattr(mod, "INTERVAL_MIN", 15) or 15),
                    "run": getattr(mod, "run", None)})
            except Exception as e:
                logger.warning("custom check %s битый: %s", fn, e)
        return {"ok": True, "count": len(self._mods)}

    def run_all(self, force=False):
        out = []
        now = time.time()
        for m in self._mods:
            if not callable(m.get("run")):
                continue
            key = m["path"]
            if not force and now - self._last_run.get(key, 0) < \
                    m["interval_min"] * 60:
                prev = next((r for r in self._results
                             if r["name"] == m["name"]), None)
                if prev:
                    out.append(prev)
                continue
            t0 = time.time()
            try:
                r = m["run"]() or {}
                ok = bool(r.get("ok"))
                text = str(r.get("text") or "")[:200]
            except Exception as e:
                ok, text = False, f"ошибка проверки: {e}"
            ms = round((time.time() - t0) * 1000)
            self._last_run[key] = time.time()
            item = {"name": m["name"], "ok": ok, "text": text, "ms": ms}
            out.append(item)
            self._results = [x for x in self._results
                             if x["name"] != m["name"]] + [item]
            if not ok:
                try:
                    hid = self.svc.inventory.resolve_host_id(
                        self.svc.infra.gateway_ip() and
                        socket.gethostname())
                    if hid:
                        self.svc.inventory.note_event(
                            hid, "custom", "WARN", "custom_check",
                            f"{m['name']}: {text}",
                            dedup_key=f"cc:{m['name']}:"
                                      f"{datetime.now():%Y%m%d%H}",
                            dedup_hours=1)
                except Exception:
                    pass
        return {"ok": True, "results": out}

    def results(self):
        return {"results": self._results, "count": len(self._mods)}
