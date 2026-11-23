"""
Интеграция с Proxmox VE: опрос нод и виртуальных машин.

Чистый stdlib (urllib), JSON API Proxmox (/api2/json). Токен — API-токен
(создаётся в PVE: Datacenter -> Permissions -> API Tokens). TLS-сертификат
самоподписанный, поэтому verify = False по умолчанию.
"""

import json
import logging
import threading
from datetime import datetime
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


def _now_iso():
    return datetime.now().isoformat()


class ProxmoxClient:
    def __init__(self, service):
        self.svc = service
        self._lock = threading.Lock()
        self.last_status = {"ok": False, "nodes": [], "vms": [], "checked": None,
                            "error": ""}
        self._ensure()

    def _ensure(self):
        self.svc.db.execute(
            """CREATE TABLE IF NOT EXISTS proxmox_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                nodes TEXT NOT NULL,
                vms TEXT NOT NULL)""")

    def _cfg(self):
        return self.svc.cfg.get("proxmox", {}) or {}

    def _enabled(self):
        cfg = self._cfg()
        return bool(cfg.get("enabled")) and bool(cfg.get("host")) \
            and bool(cfg.get("token_id")) and bool(cfg.get("token_secret"))

    def _request(self, path):
        cfg = self._cfg()
        host = cfg["host"].strip().rstrip("/")
        if not host.startswith("http"):
            host = "https://" + host
        port = int(cfg.get("port") or 8006)
        url = f"{host}:{port}/api2/json/{path.lstrip('/')}"
        req = Request(url, headers={
            "Authorization": f"PVEAPIToken={cfg['token_id']}={cfg['token_secret']}",
            "Content-Type": "application/json",
        })
        with urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
        return data.get("data", data)

    def poll(self):
        """Опрос нод и VM. Сохраняет последний результат в БД."""
        if not self._enabled():
            self.last_status = {"ok": False, "nodes": [], "vms": [],
                                "checked": _now_iso(),
                                "error": "прокси-клиент отключён в конфиге"}
            return self.last_status
        try:
            nodes = self._request("nodes") or []
            out_nodes = []
            for n in nodes:
                out_nodes.append({
                    "node": n.get("node"), "status": n.get("status"),
                    "cpu": round(float(n.get("cpu") or 0) * 100, 1),
                    "maxcpu": n.get("maxcpu"), "mem": round(
                        (n.get("mem") or 0) / 1073741824, 2),
                    "maxmem": round((n.get("maxmem") or 0) / 1073741824, 2),
                    "uptime": n.get("uptime"),
                })
            vms = self._request("cluster/resources?type=vm") or []
            out_vms = []
            for v in vms:
                out_vms.append({
                    "vmid": v.get("vmid"), "name": v.get("name"),
                    "type": "vm" if v.get("type") == "qemu" else "lxc",
                    "status": v.get("status"), "node": v.get("node"),
                    "cpu": round(float(v.get("cpu") or 0) * 100, 1),
                    "maxcpu": v.get("maxcpu"),
                    "mem": round((v.get("mem") or 0) / 1073741824, 2),
                    "maxmem": round((v.get("maxmem") or 0) / 1073741824, 2),
                    "disk": round((v.get("disk") or 0) / 1073741824, 2),
                })
            with self._lock:
                self.last_status = {
                    "ok": True, "nodes": out_nodes, "vms": out_vms,
                    "checked": _now_iso(), "error": "",
                }
            try:
                self.svc.db.execute(
                    "INSERT INTO proxmox_status (ts, nodes, vms) VALUES (?,?,?)",
                    (_now_iso(),
                     json.dumps(out_nodes, ensure_ascii=False),
                     json.dumps(out_vms, ensure_ascii=False)))
            except Exception as e:
                logger.debug("proxmox save: %s", e)
        except Exception as e:
            with self._lock:
                self.last_status = {"ok": False, "nodes": [], "vms": [],
                                    "checked": _now_iso(), "error": str(e)[:200]}
        return self.last_status

    def status(self):
        with self._lock:
            return dict(self.last_status)

    # ---------- жизненный цикл ----------

    def loop(self):
        while not self.svc._stop_event.is_set():
            try:
                self.poll()
            except Exception as e:
                logger.info(f"[proxmox] {e}")
            self.svc._stop_event.wait(300)