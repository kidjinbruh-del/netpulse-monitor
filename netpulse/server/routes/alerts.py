"""Alerts routes: список алертов и подтверждение."""
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from netpulse.server.dependencies import get_ctx, get_service

router = APIRouter(prefix="/api", tags=["alerts"])


class AlertsAckBody(BaseModel):
    id: int = 0


@router.get("/alerts")
async def get_alerts(
    limit: int = Query(80, ge=1, le=300),
    monitor= get_service("monitor"),
    ctx= Depends(get_ctx),
):
    try:
        rows = ctx.db.execute(
            """SELECT id, timestamp, alert_type, message, source, acknowledged
               FROM alerts ORDER BY id DESC LIMIT ?""",
            (limit,), fetch=True) or []
    except Exception:
        rows = []
    try:
        unread = ctx.db.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE acknowledged = 0", fetch=True)
        unread_n = (unread[0]["n"] if unread else 0) or 0
    except Exception:
        unread_n = 0
    try:
        live = list(monitor.live_alerts or [])[:20]
    except Exception:
        live = []
    return {"alerts": rows, "unread": unread_n, "live": live}


@router.post("/alertsack")
async def ack_alerts(body: AlertsAckBody, ctx= Depends(get_ctx)):
    try:
        if body.id:
            ctx.db.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (body.id,))
        else:
            ctx.db.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
    except Exception:
        pass
    return {"ok": True}
