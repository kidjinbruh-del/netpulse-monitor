"""LAN routes: устройства, сканирование сети, алиасы, port scan."""
import asyncio
import re
import socket

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from netpulse.monitor import PortScanner
from netpulse.server.dependencies import get_ctx, get_service

router = APIRouter(prefix="/api", tags=["lan"])


class LanAliasBody(BaseModel):
    mac: str = ""
    alias: str = ""


class PortScanBody(BaseModel):
    host: str = ""
    ports: list = []


SAFE_TARGET = re.compile(r"^[A-Za-z0-9._\-]{1,253}$")
SAFE_MAC = re.compile(r"^[0-9A-Fa-f:\.\-]{12,17}$")


def _require_lan(monitor):
    lan = monitor.lan
    if lan is None:
        raise HTTPException(503, "LAN-сканер недоступен (monitor backend degraded)")
    return lan


@router.get("/landevices")
async def lan_devices(monitor= get_service("monitor")):
    lan = _require_lan(monitor)
    try:
        base, my_ip = await asyncio.to_thread(lan.local_subnet)
        subnet = f"{base}0/24"
    except Exception:
        base, my_ip, subnet = "", "", ""
    try:
        self_name = socket.gethostname()
    except Exception:
        self_name = ""
    try:
        devices = await asyncio.to_thread(lan.devices_from_db)
    except Exception:
        devices = []
    return {"devices": devices, "subnet": subnet, "self_ip": my_ip, "self_name": self_name}


@router.post("/lanscan")
async def lan_scan(monitor= get_service("monitor")):
    lan = _require_lan(monitor)
    try:
        devices = await asyncio.wait_for(asyncio.to_thread(lan.scan), timeout=95)
        return {"devices": devices or []}
    except asyncio.TimeoutError:
        raise HTTPException(504, "скан превысил таймаут")
    except Exception as e:
        return {"devices": [], "error": str(e)}


@router.post("/lanalias")
async def lan_alias(body: LanAliasBody, ctx= Depends(get_ctx)):
    mac = (body.mac or "").strip()
    alias = (body.alias or "").strip()[:80]
    if not SAFE_MAC.match(mac):
        raise HTTPException(400, "некорректный MAC")
    try:
        rowid = ctx.db.execute(
            "UPDATE lan_devices SET alias = ? WHERE mac = ?", (alias, mac)
        )
    except Exception as e:
        raise HTTPException(500, str(e))
    return {"ok": bool(rowid), "mac": mac, "alias": alias}


@router.post("/portscan")
async def port_scan(body: PortScanBody):
    host = (body.host or "").strip()
    if not SAFE_TARGET.match(host):
        raise HTTPException(400, "некорректный хост")
    ports = None
    if isinstance(body.ports, list) and body.ports:
        try:
            ports = [int(p) for p in body.ports][:100]
        except Exception:
            ports = None
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(PortScanner.tcp_scan, host, ports), timeout=65
        )
        return result
    except asyncio.TimeoutError:
        raise HTTPException(504, "таймаут сканирования")
    except Exception as e:
        raise HTTPException(500, str(e))
