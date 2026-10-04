"""Planner/watchdog routes: плановые работы и обход парка."""
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from netpulse.server.dependencies import get_config, get_service

router = APIRouter(prefix="/api", tags=["planner"])


class PlannerDoneBody(BaseModel):
    name: str = ""
    actor: str = ""


@router.get("/planner")
async def planner_list(
    planner= get_service("planner"),
    config= Depends(get_config),
):
    return {"tasks": planner.status_list(),
            "enabled": bool(config.planner.enabled)}


@router.post("/plannerdone")
async def planner_done(
    body: PlannerDoneBody,
    request: Request,
    planner= get_service("planner"),
):
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(400, "нужно имя задачи")
    actor = getattr(request.state, "user", None) or body.actor or "admin"
    return await asyncio.to_thread(planner.mark_done, name, actor)


@router.post("/watchdogpoll")
async def watchdog_poll(watchdog= get_service("watchdog")):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(watchdog.poll_cycle), timeout=245)
    except asyncio.TimeoutError:
        raise HTTPException(504, "обход превысил таймаут")
