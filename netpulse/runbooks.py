"""
Runbook Runner: типовые операции отдела как «кнопки».
Определения — JSON-файлы в netpulse/runbooks/*.json:
{
  "id": "restart-spooler",
  "name": "Перезапустить очередь печати",
  "description": "Спулер на удалённой машине",
  "scope": "remote",            // remote -> через Invoke-Command, local -> здесь
  "command": "Restart-Service -Name Spooler -ComputerName {host} -Force",
  "params": [{"name": "host", "required": true}]
}
Параметры строго [A-Za-z0-9._-] — никаких кавычек и pipe. Каждый запуск
пишется в runbook_log (кто, когда, код выхода, хвост вывода).
"""

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime

from core.utils import decode_process_output

logger = logging.getLogger(__name__)

RB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runbooks")
PARAM_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
EXEC_TIMEOUT = 120


def _now_iso():
    return datetime.now().isoformat()


EXAMPLE_SPOOLER = {
    "id": "restart-spooler",
    "name": "Перезапустить очередь печати (удалённо)",
    "description": "Лечит «принтер не печатает» без выезда: спулер на машине юзера",
    "scope": "remote",
    "command": "Restart-Service -Name Spooler -Force",
    "params": [{"name": "host", "required": True}],
}

EXAMPLE_DISKS = {
    "id": "disk-space-local",
    "name": "Диски этого сервера",
    "description": "Быстрый взгляд на свободное место локально",
    "scope": "local",
    "command": ("Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | "
                "Select-Object DeviceID,"
                "@{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}} "
                "| Format-Table -AutoSize"),
    "params": [],
}


class RunbookRunner:
    def __init__(self, service):
        self.svc = service
        self._lock = threading.Lock()
        self._defs = {}
        self.load()

    # ---------- загрузка ----------

    def load(self):
        with self._lock:
            self._defs = {}
            try:
                if not os.path.isdir(RB_DIR):
                    os.makedirs(RB_DIR, exist_ok=True)
                    for ex in (EXAMPLE_SPOOLER, EXAMPLE_DISKS):
                        path = os.path.join(RB_DIR, f"{ex['id']}.json")
                        with open(path, "w", encoding="utf-8") as f:
                            json.dump(ex, f, ensure_ascii=False, indent=2)
            except Exception as e:
                logger.warning("Не удалось создать примеры runbook: %s", e)

            try:
                for fn in sorted(os.listdir(RB_DIR)):
                    if not fn.endswith(".json"):
                        continue
                    try:
                        with open(os.path.join(RB_DIR, fn),
                                  encoding="utf-8") as f:
                            rb = json.load(f)
                        rid = str(rb.get("id") or fn[:-5])
                        rb["id"] = rid
                        self._defs[rid] = rb
                    except Exception as e:
                        logger.warning("Runbook %s битый: %s", fn, e)
            except Exception as e:
                logger.warning("Каталог runbooks недоступен: %s", e)
        return {"ok": True, "count": len(self._defs)}

    def reload(self):
        return self.load()

    def list(self):
        return [{
            "id": rb["id"], "name": rb.get("name", rb["id"]),
            "description": rb.get("description", ""),
            "scope": rb.get("scope", "local"),
            "params": [p.get("name") for p in (rb.get("params") or [])],
        } for rb in self._defs.values()]

    # ---------- выполнение ----------

    def _validate_params(self, rb, params):
        clean = {}
        declared = rb.get("params") or []
        names = {p.get("name"): bool(p.get("required")) for p in declared}
        for k, v in (params or {}).items():
            v = str(v).strip()
            if not PARAM_RE.match(k) or not PARAM_RE.match(v):
                return None, f"недопустимый параметр {k}"
            clean[k] = v
        for pname, required in names.items():
            if required and pname not in clean:
                return None, f"не хватает параметра {pname}"
        unknown = set(clean) - set(names)
        if unknown:
            return None, f"лишние параметры: {', '.join(sorted(unknown))}"
        return clean, None

    def execute(self, rb_id, params=None, actor="admin"):
        rb = self._defs.get(str(rb_id))
        if not rb:
            return {"ok": False, "error": "runbook не найден"}
        clean, err = self._validate_params(rb, params)
        if err:
            return {"ok": False, "error": err}

        scope = rb.get("scope", "local")
        command = str(rb.get("command", ""))
        host = clean.get("host", "")
        placeholders = set(PLACEHOLDER_RE.findall(command))
        missing = placeholders - set(clean)
        if missing:
            return {"ok": False,
                    "error": f"не заданы плейсхолдеры: {', '.join(missing)}"}

        try:
            # Заменяем только известные {плейсхолдеры}, скобки PowerShell
            # (например @{n='FreeGB'}) не трогаем
            rendered = PLACEHOLDER_RE.sub(
                lambda m: clean.get(m.group(1), m.group(0)), command)
        except Exception as e:
            return {"ok": False, "error": f"шаблон команды битый: {e}"}

        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        if scope == "remote":
            if not host:
                return {"ok": False, "error": "для remote нужен host"}
            cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                   f"Invoke-Command -ComputerName {host} "
                   f"-ScriptBlock {{ {rendered} }}"]
        else:
            cmd = ["powershell", "-NoProfile", "-NonInteractive",
                   "-Command", rendered]

        t0 = time.time()
        exit_code, output = -1, ""
        try:
            proc = subprocess.run(cmd, capture_output=True,
                                  timeout=EXEC_TIMEOUT, creationflags=flags)
            exit_code = proc.returncode
            output = decode_process_output(
                (proc.stdout or b"") + (proc.stderr or b""))[:2000]
        except subprocess.TimeoutExpired:
            output = f"таймаут {EXEC_TIMEOUT}s"
        except Exception as e:
            output = str(e)[:500]
        elapsed = round(time.time() - t0, 1)

        self.svc.db.execute(
            """INSERT INTO runbook_log
               (timestamp, runbook, params, actor, target, exit_code, output)
               VALUES (?,?,?,?,?,?,?)""",
            (_now_iso(), rb_id, json.dumps(clean, ensure_ascii=False),
             str(actor)[:60], host or "-", exit_code, output))

        ok = exit_code == 0
        name = rb.get("name", rb_id)
        try:
            self.svc.push_alert(
                "RUNBOOK_EXEC" if ok else "RUNBOOK_FAIL",
                f"{name}" + (f" @ {host}" if host else "") +
                ("" if ok else f" — код {exit_code}"), "runbook", rate=10)
            inv = getattr(self.svc, "inventory", None)
            if inv and host:
                hid = inv.resolve_host_id(host)
                if hid:
                    inv.note_event(hid, "runbook", "LOW" if ok else "MEDIUM",
                                   "runbook",
                                   f"{name}: {'выполнено' if ok else 'ошибка'}",
                                   dedup_key=f"{rb_id}:{host}:"
                                             f"{datetime.now():%Y%m%d%H}",
                                   dedup_hours=1)
        except Exception:
            pass

        return {"ok": ok, "exit_code": exit_code, "seconds": elapsed,
                "output": output.strip()}

    def recent_log(self, limit=50):
        limit = min(max(int(limit or 50), 1), 200)
        return self.svc.db.execute(
            """SELECT timestamp, runbook, actor, target, exit_code, output
               FROM runbook_log ORDER BY id DESC LIMIT ?""",
            (limit,), fetch=True) or []
