"""Journal routes: журнал работ отдела."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from netpulse.server.dependencies import get_service

router = APIRouter(prefix="/api", tags=["journal"])


class JournalAddBody(BaseModel):
    text: str = ""
    source: str = "manual"
    host: str = ""
    user: str = ""
    minutes: int = 0


class JournalDelBody(BaseModel):
    id: int = 0


@router.get("/journal")
async def journal_list(
    limit: int = Query(150, ge=1, le=500),
    source: str = Query(""),
    q: str = Query("", alias="q"),
    journal= get_service("journal"),
):
    return {"entries": journal.list_entries(
        limit, source or None, q or None)}


@router.post("/journaladd")
async def journal_add(body: JournalAddBody, journal= get_service("journal")):
    if not (body.text or "").strip():
        raise HTTPException(400, "пустой текст записи")
    return journal.add(
        text=body.text,
        source=body.source or "manual",
        host=body.host or None,
        user_name=body.user or None,
        minutes=body.minutes or 0,
    )


@router.post("/journaldel")
async def journal_delete(body: JournalDelBody, journal= get_service("journal")):
    return journal.delete(body.id)


@router.get("/journalreport")
async def journal_report(
    days: str = Query("30"),
    journal= get_service("journal"),
    inventory= get_service("inventory"),
):
    rep = journal.month_report(days)
    try:
        rep["worst_hosts"] = inventory.worst_hosts(3)
    except Exception:
        rep["worst_hosts"] = []
    return rep
