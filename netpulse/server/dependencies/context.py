"""FastAPI Depends: доступ к AppContext, Config и сервисам."""
from __future__ import annotations
from typing import TYPE_CHECKING

from fastapi import Depends, HTTPException, Request

if TYPE_CHECKING:
    from netpulse.context import AppContext
    from netpulse.config import Config
    from netpulse.services.base import BaseService


def get_ctx(request: Request) -> "AppContext":
    ctx = getattr(request.app.state, "ctx", None)
    if ctx is None:
        raise HTTPException(503, "Application context not initialized")
    return ctx


def get_config(request: Request) -> "Config":
    config = getattr(request.app.state, "config", None)
    if config is None:
        raise HTTPException(503, "Application config not initialized")
    return config


def get_service(name: str):
    def _get(request: Request) -> "BaseService":
        ctx = get_ctx(request)
        svc = ctx.get_service(name)
        if svc is None:
            raise HTTPException(503, f"Service {name} not available")
        return svc
    return Depends(_get)
