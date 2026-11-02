"""
Интеграция с Proxmox VE: опрос нод и виртуальных машин.

Чистый stdlib (urllib), JSON API Proxmox (/api2/json). Токен — API-токен
(создаётся в PVE: Datacenter -> Permissions -> API Tokens). TLS проверяется
по умолчанию; частный CA задаётся через ca_file.
"""

import json
import logging
import threading
import os
import ssl
from urllib.parse import urlsplit
from datetime import datetime
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


def _now_iso():
    return datetime.now().isoformat()


class ProxmoxClient:
    def __init__(self, service):
        self.svc = service
        self._lock = threading.Lock()
        self._poll_lock = threading.Lock()
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
            and bool(cfg.get("token_id")) and bool(self._secret())

    def _secret(self):
        return os.environ.get(self._cfg().get('token_env') or 'NP_PROXMOX_TOKEN') or self._cfg().get('token_secret') or ''

    def _request(self, path):
        cfg = self._cfg()
        host = cfg["host"].strip().rstrip("/")
        if "://" not in host:
            host = "https://" + host
        parsed = urlsplit(host)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('','/') or parsed.query or parsed.fragment:
            raise ValueError('Proxmox host must be an HTTPS origin')
        port = parsed.port or int(cfg.get("port") or 8006)
        name = '['+parsed.hostname+']' if ':' in parsed.hostname else parsed.hostname
        url = f"https://{name}:{port}/api2/json/{path.lstrip('/')}"
        context = ssl.create_default_context(cafile=cfg.get('ca_file') or None)
        if cfg.get('verify_tls') is False:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        req = Request(url, headers={
            "Authorization": f"PVEAPIToken={cfg['token_id']}={self._secret()}",
            "Content-Type": "application/json",
        })
        with urlopen(req, timeout=10, context=context) as r:
            data = json.loads(r.read().decode("utf-8"))
        return data.get("data", data)

    def poll(self):
        if not self._poll_lock.acquire(blocking=False):
            return self.status()
        try:
            return self._poll()
        finally:
            self._poll_lock.release()

    def _poll(self):
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
                    "cpu": round(float(n["cpu"]) * 100, 1) if n.get("cpu") is not None else None,
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
                    "cpu": round(float(v["cpu"]) * 100, 1) if v.get("cpu") is not None else None,
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
                self.last_status = {**self.last_status, "ok": False,
                                    "attempted": _now_iso(), "stale": bool(self.last_status.get('checked')),
                                    "error": "Опрос PVE не выполнен. Проверьте HTTPS, CA, API-токен, права и доступность узла"}
        return self.last_status

    def status(self):
        with self._lock:
            return {**self.last_status, 'enabled': bool(self._cfg().get('enabled')),
                    'configured': self._enabled(), 'verify_tls': self._cfg().get('verify_tls') is not False}

    # ---------- жизненный цикл ----------

    def loop(self):
        while not self.svc._stop_event.is_set():
            try:
                self.poll()
            except Exception as e:
                logger.info(f"[proxmox] {e}")
            self.svc._stop_event.wait(300)
