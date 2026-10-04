"""Pages routes: серверный рендеринг Jinja2 (первый paint дашборда)."""
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse

from netpulse.server.dependencies import get_config, get_service
from netpulse.server.templates import render

router = APIRouter(tags=["pages"])


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    monitor= get_service("monitor"),
    inventory= get_service("inventory"),
    config= Depends(get_config),
):
    try:
        state = monitor.get_snapshot() or {}
    except Exception:
        state = {}
    try:
        state["forecast"] = monitor.forecast_speed()
    except Exception:
        state["forecast"] = {}
    try:
        have = len(monitor.get_history(600))
    except Exception:
        have = 0
    try:
        hosts = inventory.list_hosts()
    except Exception:
        hosts = []
    html = render("pages/dashboard.html", {
        "state": state,
        "hosts": hosts or [],
        "forecast_progress": {"have": have, "need": 30},
        "auth_enabled": bool(config.web.auth_enabled),
    })
    return HTMLResponse(html)
