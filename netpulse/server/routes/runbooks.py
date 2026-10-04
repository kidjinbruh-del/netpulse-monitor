"""Runbooks routes: список и выполнение runbook'ов."""
import asyncio
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from netpulse.server.dependencies import get_service

router = APIRouter(prefix="/api", tags=["runbooks"])


class RunbookExecBody(BaseModel):
    name: str = ""
    params: Dict[str, Any] = {}
    actor: str = ""


@router.get("/runbooks")
async def runbooks_list(runbooks= get_service("runbooks")):
    return {"runbooks": runbooks.list(),
            "log": runbooks.recent_log(20)}


@router.post("/runbookexec")
async def runbook_exec(
    body: RunbookExecBody,
    request: Request,
    runbooks= get_service("runbooks"),
):
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(400, "нужно имя runbook")
    actor = getattr(request.state, "user", None) or body.actor or "admin"
    params = body.params if isinstance(body.params, dict) else {}
    res = await asyncio.to_thread(runbooks.execute, name, params, actor)
    if not (res or {}).get("ok"):
        raise HTTPException(400, res)
    return res
