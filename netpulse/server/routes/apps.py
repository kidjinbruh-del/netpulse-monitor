"""Apps routes: мониторинг приложений + Windows Firewall."""
import re

import psutil
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from netpulse.server.dependencies import get_service

router = APIRouter(prefix="/api", tags=["apps"])


class FwBlockIpBody(BaseModel):
    ip: str = ""


class FwBlockAppBody(BaseModel):
    pid: int = 0
    path: str = ""


class FwUnblockBody(BaseModel):
    name: str = ""


@router.get("/apps")
async def get_apps(monitor= get_service("monitor")):
    procs = monitor.procmon_top_io(40)
    try:
        admin = bool((monitor.snapshot or {}).get("mode", {}).get("admin"))
    except Exception:
        admin = False
    return {"apps": procs, "admin": admin}


@router.get("/appnewconn")
async def get_app_new_connections(monitor= get_service("monitor")):
    return {"events": monitor.procmon_new_connections(80)}


@router.get("/appexe")
async def get_app_exe(pid: int = Query(0)):
    try:
        exe = psutil.Process(pid).exe()
        return {"pid": pid, "exe": exe or ""}
    except Exception:
        return {"pid": 0, "exe": "", "error": "процесс недоступен"}


@router.get("/firewallrules")
async def get_firewall_rules(firewall= get_service("firewall")):
    return firewall.list_rules()


@router.post("/fwblockip")
async def post_fw_block_ip(
    body: FwBlockIpBody,
    monitor= get_service("monitor"),
    firewall= get_service("firewall"),
):
    ip = (body.ip or "").strip()
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
        raise HTTPException(400, "нужен IPv4")
    res = firewall.block_ip(ip)
    if res.get("ok"):
        monitor.push_alert("FIREWALL_BLOCK", f"IP {ip} заблокирован в Windows Firewall", "firewall")
    return res


@router.post("/fwblockapp")
async def post_fw_block_app(
    body: FwBlockAppBody,
    monitor= get_service("monitor"),
    firewall= get_service("firewall"),
):
    path = (body.path or "").strip()
    if not path and body.pid:
        try:
            path = psutil.Process(body.pid).exe() or ""
        except Exception:
            path = ""
    import os
    if not path or not os.path.exists(path):
        raise HTTPException(
            400, "путь к exe не найден (запустите от админа или укажите вручную)"
        )
    res = firewall.block_app(path)
    if res.get("ok"):
        monitor.push_alert(
            "FIREWALL_BLOCK_APP", f"Приложение заблокировано: {path}", "firewall"
        )
    res["path"] = path
    return res


@router.post("/fwunblock")
async def post_fw_unblock(
    body: FwUnblockBody,
    firewall= get_service("firewall"),
):
    res = firewall.unblock(body.name or "")
    if res.get("ok") is False and res.get("error"):
        raise HTTPException(400, res["error"])
    return res
