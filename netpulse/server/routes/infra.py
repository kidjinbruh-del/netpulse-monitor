"""Infra routes: SNMP-инфраструктура (роутеры/свитчи/серверы)."""
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from netpulse.server.dependencies import get_config, get_service

router = APIRouter(prefix="/api", tags=["infra"])


class InfraScanBody(BaseModel):
    community: str = ""


class InfraDtypeBody(BaseModel):
    host_id: int = 0
    dtype: str = ""


@router.get("/infra")
async def infra_list(
    infra= get_service("infra"),
    config= Depends(get_config),
):
    return {"devices": infra.device_list(),
            "gateway": infra.gateway_ip(),
            "community": config.infra.community or "public"}


@router.post("/infrascan")
async def infra_scan(body: InfraScanBody, infra= get_service("infra")):
    community = (body.community or "").strip() or None
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(infra.scan_infra, community), timeout=245)
    except asyncio.TimeoutError:
        raise HTTPException(504, "опрос превысил таймаут")


@router.get("/infradtype")
async def infra_dtype_get(
    host_id: int = Query(0),
    dtype: str = Query(""),
    infra= get_service("infra"),
):
    if not host_id:
        raise HTTPException(400, "нужен host_id")
    return await asyncio.to_thread(infra.set_dtype, host_id, dtype or "")


@router.post("/infradtype")
async def infra_dtype_post(body: InfraDtypeBody, infra= get_service("infra")):
    if not body.host_id:
        raise HTTPException(400, "нужен host_id")
    return await asyncio.to_thread(infra.set_dtype, body.host_id, body.dtype or "")


@router.get("/infradiff")
async def infra_diff(id: int = Query(0), infra= get_service("infra")):
    if not id:
        raise HTTPException(400, "нужен числовой id")
    return await asyncio.to_thread(infra.snap_diff, id)
