"""Capture routes: захват пакетов."""
import asyncio

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from netpulse.server.dependencies import get_service

router = APIRouter(prefix="/api", tags=["capture"])


class CaptureStartBody(BaseModel):
    proto: str = ""


def _require_capture(monitor):
    cap = monitor.capture
    if cap is None:
        raise HTTPException(503, "захват пакетов недоступен (monitor backend degraded)")
    return cap


@router.post("/capturestart")
async def capture_start(body: CaptureStartBody, monitor= get_service("monitor")):
    cap = _require_capture(monitor)
    return await asyncio.to_thread(cap.start, body.proto or None)


@router.post("/capturestop")
async def capture_stop(monitor= get_service("monitor")):
    cap = _require_capture(monitor)
    await asyncio.to_thread(cap.stop)
    return {"ok": True}


@router.get("/capturestate")
async def capture_state(monitor= get_service("monitor")):
    cap = _require_capture(monitor)
    return await asyncio.to_thread(cap.snapshot, 120)
