"""Core routes: состояние, история, интерфейсы, соединения, процессы."""
from fastapi import APIRouter, Query

from netpulse.server.dependencies import get_service

router = APIRouter(prefix="/api", tags=["core"])


@router.get("/state")
async def get_state(monitor= get_service("monitor")):
    snap = monitor.get_snapshot() or {}
    snap["forecast"] = monitor.forecast_speed()
    try:
        have = len(monitor.get_history(600))
    except Exception:
        have = 0
    snap["forecast_progress"] = {"have": have, "need": 30}
    snap["quota"] = monitor.quota_usage()
    return snap


@router.get("/history")
async def get_history(
    minutes: int = Query(30, ge=1, le=30),
    monitor= get_service("monitor"),
):
    seconds = min(max(minutes * 60, 60), 1800)
    rows = monitor.get_history(seconds)
    return {"points": [
        {"t": t, "down_kbps": round(d, 1), "up_kbps": round(u, 1), "ping_ms": p}
        for t, d, u, p in rows
    ]}


@router.get("/dbhistory")
async def get_db_history(
    hours: int = Query(24, ge=1, le=168),
    monitor= get_service("monitor"),
):
    return {"hours": hours, "buckets": monitor.db_history(hours)}


@router.get("/interfaces")
async def get_interfaces(monitor= get_service("monitor")):
    return monitor.interfaces_info()


@router.get("/connections")
async def get_connections(
    listening: bool = Query(False),
    limit: int = Query(150, ge=1, le=500),
    monitor= get_service("monitor"),
):
    conns = monitor.connections(limit=limit + 50, include_listening=listening)
    if isinstance(conns, dict):
        return conns
    est = [c for c in conns if c.get("status") != "LISTEN"]
    data = (conns if listening else est)[:limit]
    return {"count": len(data), "connections": data}


@router.get("/topprocesses")
async def get_top_processes(monitor= get_service("monitor")):
    return {"processes": monitor.top_processes_by_conns()}
