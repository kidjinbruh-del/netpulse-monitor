"""Security routes: IDS feed, сканы, whitelist."""
import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from core.security import SecurityScanner
from netpulse.server.dependencies import get_config, get_ctx, get_service
from netpulse.server.jobs import jobs

router = APIRouter(prefix="/api", tags=["security"])


class SecurityScanBody(BaseModel):
    quick: bool = False


class IdsWlBody(BaseModel):
    process: str = ""
    ports: str = ""
    path: str = ""


@router.get("/idsfeed")
async def ids_feed(monitor= get_service("monitor")):
    return {"events": monitor.procmon_ids_feed(80)}


def _run_quick(ports: list) -> dict:
    return {
        "Подозрительные соединения":
            SecurityScanner.detect_suspicious_connections(ports),
        "HOSTS файл": SecurityScanner.check_hosts_file(),
    }


def _run_full(ports: list, whitelist_match) -> dict:
    res = SecurityScanner.run_full_scan(ports)
    hidden = res.get("Скрытые процессы") or []
    res["Скрытые процессы"] = [
        h for h in hidden if not whitelist_match(h.get("path") or "")
    ]
    return res


@router.post("/securityscan")
async def security_scan(
    body: SecurityScanBody,
    monitor= get_service("monitor"),
    infra= get_service("infra"),
    config= Depends(get_config),
):
    quick = bool(body.quick)
    ports = list(config.security.suspicious_ports or [])

    async def _job():
        if quick:
            res = await asyncio.to_thread(_run_quick, ports)
        else:
            res = await asyncio.to_thread(_run_full, ports, infra.whitelist_match_hidden)
        total = sum(len(v) for v in res.values()) if isinstance(res, dict) else 0
        monitor.push_alert(
            "SECURITY_SCAN",
            f"Скан завершён: угроз {total} ({'быстрый' if quick else 'полный'})",
            "scanner",
        )
        return res

    return {"job": jobs.submit(_job())}


@router.get("/securityresult")
async def security_result(job: str = Query("")):
    record = jobs.get(job or "")
    if record is None:
        raise HTTPException(404, "задача не найдена")
    return record


@router.post("/idswl")
async def ids_wl_add(
    body: IdsWlBody,
    monitor= get_service("monitor"),
    config= Depends(get_config),
    ctx= Depends(get_ctx),
):
    rule = {k: (getattr(body, k) or "").strip() for k in ("process", "ports", "path")}
    rule = {k: v for k, v in rule.items() if v}
    if not rule:
        raise HTTPException(400, "пустое правило")
    wl = config.ids.whitelist
    if rule not in wl:
        wl.append(rule)
    # Персистим в config.json
    try:
        from netpulse.config import load_config_dict, save_config
        raw = load_config_dict("config.json")
        raw.setdefault("ids", {})["whitelist"] = [dict(r) for r in wl]
        save_config(raw, "config.json")
    except Exception:
        pass
    try:
        monitor.push_alert("IDS_WL", f"Whitelist +: {rule}", "security")
    except Exception:
        pass
    return {"ok": True, "whitelist": wl}
