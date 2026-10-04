"""Inventory routes: парк хостов, события, софт, действия."""
import asyncio
from typing import Any, Dict

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel

from netpulse.server.dependencies import get_service

router = APIRouter(prefix="/api", tags=["inventory"])


class WolBody(BaseModel):
    host: str = ""


@router.get("/hosts")
async def hosts_list(
    inventory= get_service("inventory"),
    watchdog= get_service("watchdog"),
):
    try:
        wd = watchdog.status()
    except Exception:
        wd = {}
    return {"hosts": inventory.list_hosts(), "watchdog": wd}


@router.get("/hostdetail")
async def host_detail(
    id: int = Query(0),
    inventory= get_service("inventory"),
    softwareinv= get_service("softwareinv"),
):
    if not id:
        raise HTTPException(400, "нужен числовой id")
    d = inventory.host_detail(id)
    if isinstance(d, dict) and d.get("error"):
        raise HTTPException(404, d)
    try:
        d["software"] = softwareinv.for_host(id, 200)
    except Exception:
        d["software"] = []
    try:
        d["karma_hist"] = inventory.karma_history(id)
    except Exception:
        d["karma_hist"] = []
    return d


@router.get("/events")
async def events_feed(
    limit: int = Query(80, ge=1, le=300),
    host_id: int = Query(0),
    inventory= get_service("inventory"),
):
    return {"events": inventory.recent_events(limit, host_id or None)}


@router.get("/softsearch")
async def software_search(
    q: str = Query(""),
    softwareinv= get_service("softwareinv"),
):
    return {"results": softwareinv.search(q or ""),
            "stats": softwareinv.stats()}


@router.post("/invreport")
async def inv_report(
    body: Dict[str, Any] = Body(default={}),
    softwareinv= get_service("softwareinv"),
):
    try:
        return await asyncio.to_thread(softwareinv.receive_report, body or {})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/healthrecompute")
async def health_recompute(inventory= get_service("inventory")):
    return await asyncio.to_thread(inventory.recompute_health)


@router.post("/wol")
async def wol_wake(body: WolBody, wol= get_service("wol")):
    return await asyncio.to_thread(wol.wake, (body.host or None))


@router.get("/diskforecast")
async def disk_forecast(watchdog= get_service("watchdog")):
    return await asyncio.to_thread(watchdog.disk_forecast)
