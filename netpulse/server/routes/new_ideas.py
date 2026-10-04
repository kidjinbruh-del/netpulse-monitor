"""New-ideas routes: SLA, geo-карта, прогнозы, L2, CVE, Proxmox, отчёты."""
import asyncio

from fastapi import APIRouter, Depends, Query

from netpulse.server.dependencies import get_ctx, get_service

router = APIRouter(prefix="/api", tags=["new_ideas"])


@router.get("/sla")
async def sla(days: int = Query(30, ge=1, le=365), sla= get_service("sla")):
    return await asyncio.to_thread(sla.period, days)


@router.get("/geomap")
async def geomap(limit: int = Query(150, ge=1, le=500), geo= get_service("geo")):
    return await asyncio.to_thread(geo.attack_map, limit)


@router.get("/ramforecast")
async def ram_forecast(ram_forecast= get_service("ram_forecast")):
    return await asyncio.to_thread(ram_forecast.forecast)


@router.get("/l2map")
async def l2_map(mac: str = Query(""), l2map= get_service("l2map")):
    mac = (mac or "").strip()
    return {
        "status": await asyncio.to_thread(l2map.status),
        "ports": await asyncio.to_thread(l2map.ports_for, mac) if mac else l2map.last_ports,
        "lldp": l2map.last_lldp,
    }


@router.get("/ptrs")
async def ptrs(l2map= get_service("l2map")):
    upd = await asyncio.to_thread(l2map.resolve_ptrs)
    return {"updated": upd}


@router.post("/l2scan")
async def l2_scan(l2map= get_service("l2map")):
    return await asyncio.to_thread(l2map.scan)


@router.get("/mtrhistory")
async def mtr_history(
    hours: int = Query(24, ge=1, le=168),
    mtr_history= get_service("mtr_history"),
):
    return await asyncio.to_thread(mtr_history.entries, hours)


@router.post("/mtrfan")
async def mtr_fan(monitor= get_service("monitor")):
    from fastapi import HTTPException
    mtr = monitor.mtr
    if mtr is None:
        raise HTTPException(503, "MTR-движок недоступен")
    return await asyncio.to_thread(mtr.stats)


@router.get("/cvestatus")
async def cve_status(cve= get_service("cve")):
    return await asyncio.to_thread(cve.status)


@router.post("/cvescan")
async def cve_scan(ctx= Depends(get_ctx), cve= get_service("cve")):
    try:
        rows = ctx.db.execute(
            "SELECT name, version FROM sw_inventory LIMIT 100", fetch=True) or []
    except Exception:
        rows = []
    products = [(r["name"], r["version"]) for r in rows]
    found = await asyncio.to_thread(cve.check_products, products)
    return {"found": found, "products": len(products)}


@router.get("/proxmox")
async def proxmox_status(proxmox= get_service("proxmox")):
    return await asyncio.to_thread(proxmox.status)


@router.post("/proxmoxpoll")
async def proxmox_poll(proxmox= get_service("proxmox")):
    return await asyncio.to_thread(proxmox.poll)


@router.get("/reportpdf")
async def report_pdf(monitor= get_service("monitor")):
    return await asyncio.to_thread(monitor.weekly_report_text)
