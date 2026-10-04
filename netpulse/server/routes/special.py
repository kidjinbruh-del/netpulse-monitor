"""Special routes: SSE stream, Prometheus metrics, файлы (rdp, gposcript, отчёты)."""
import asyncio
import csv
import io
import os
import re
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse, Response
from sse_starlette.sse import EventSourceResponse

from netpulse.server.dependencies import get_ctx, get_service

router = APIRouter(tags=["special"])

SAFE_TARGET = re.compile(r"^[A-Za-z0-9._\-]{1,253}$")


@router.get("/api/stream")
async def stream_state(request: Request, monitor= get_service("monitor")):
    async def event_generator():
        deadline = asyncio.get_event_loop().time() + 3600
        while asyncio.get_event_loop().time() < deadline:
            if await request.is_disconnected():
                break
            yield {"event": "ping", "data": "ping"}
            yield {"event": "state", "data": monitor.state_json_cached()}
            await asyncio.sleep(1)

    return EventSourceResponse(event_generator())


@router.get("/metrics")
async def prometheus_metrics(monitor= get_service("monitor"), ctx= Depends(get_ctx)):
    s = monitor.get_snapshot() or {}
    ping = s.get("ping") or {}
    quality = s.get("quality") or {}
    lines = [
        "# HELP np_down_speed Current download speed KB/s",
        "# TYPE np_down_speed gauge",
        f"np_down_speed {s.get('down_kbps', 0)}",
        "# HELP np_up_speed Current upload speed KB/s",
        "# TYPE np_up_speed gauge",
        f"np_up_speed {s.get('up_kbps', 0)}",
        "# HELP np_ping_ms Current ping ms",
        "# TYPE np_ping_ms gauge",
        f"np_ping_ms {ping.get('current') or 0}",
        "# HELP np_quality_score Network quality score 0-100",
        "# TYPE np_quality_score gauge",
        f"np_quality_score {quality.get('score', 0)}",
        "# HELP np_alerts_unread Unacknowledged alerts",
        "# TYPE np_alerts_unread gauge",
        f"np_alerts_unread {s.get('alerts_unread', 0)}",
        "# HELP np_traffic_total_mb Session totals MB",
        "# TYPE np_traffic_total_mb counter",
        f"np_traffic_total_down_mb {s.get('total_down_mb', 0)}",
        f"np_traffic_total_up_mb {s.get('total_up_mb', 0)}",
    ]
    try:
        j24 = ctx.db.execute(
            """SELECT COUNT(*) AS n FROM journal
               WHERE timestamp > datetime('now','localtime','-1 day')""",
            fetch=True)
        hosts_n = ctx.db.execute("SELECT COUNT(*) AS n FROM hosts", fetch=True)
        lines += [
            "# HELP np_journal_entries_24h Journal entries last 24h",
            "# TYPE np_journal_entries_24h gauge",
            f"np_journal_entries_24h {(j24[0]['n'] if j24 else 0) or 0}",
            "# HELP np_hosts_total Known machines",
            "# TYPE np_hosts_total gauge",
            f"np_hosts_total {(hosts_n[0]['n'] if hosts_n else 0) or 0}",
        ]
    except Exception:
        pass
    return PlainTextResponse(
        "\n".join(lines),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/api/rdp")
async def rdp_download(host: str = Query("")):
    from fastapi import HTTPException
    host = (host or "").strip()
    if not SAFE_TARGET.match(host):
        raise HTTPException(400, "некорректный хост")
    content = (
        "screen mode id:i:2\r\n"
        f"full address:s:{host}\r\n"
        "username:s:\r\n"
        "compression:i:1\r\n"
        "audiomode:i:0\r\n"
    )
    data = content.encode("utf-16-le")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", host)[:40]
    return Response(
        content=data,
        media_type="application/x-rdp",
        headers={"Content-Disposition": f'attachment; filename="{safe or "session"}.rdp"'},
    )


@router.get("/api/gposcript")
async def gpo_script():
    from fastapi import HTTPException
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "gpo", "inventory.ps1",
    )
    if not os.path.isfile(path):
        raise HTTPException(404, "скрипт не найден")
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        raise HTTPException(500, "не читается")
    return Response(
        content=data,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="netpulse-inventory.ps1"'},
    )


@router.get("/journal.csv")
async def journal_csv(days: int = Query(30, ge=1, le=365), ctx= Depends(get_ctx)):
    journal = ctx.get_service("journal")
    try:
        rows = journal.list_entries(1000) if journal else []
    except Exception:
        rows = []
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
    w.writerow(["Дата/время", "Источник", "Кто/где", "Машина", "Минуты", "Запись"])
    for e in rows:
        w.writerow([e.get("timestamp", "")[:19], e.get("source", ""),
                    e.get("user_name") or "", e.get("host") or "",
                    e.get("minutes") or 0, e.get("text")])
    data = buf.getvalue().encode("utf-8-sig")
    return Response(
        content=data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="netpulse_journal_{days}d.csv"'},
    )


@router.get("/journal.txt")
async def journal_txt(days: int = Query(30, ge=1, le=365), ctx= Depends(get_ctx)):
    lines = [
        "=" * 56,
        f"ОТЧЁТ ОТДЕЛА ИТ  ({datetime.now():%Y-%m-%d %H:%M}, период {days} дн)",
        "=" * 56,
        "",
    ]
    try:
        journal = ctx.get_service("journal")
        rep = journal.month_report(str(days)) if journal else {}
        lines += [
            f"Записей в журнале : {rep.get('entries', 0)}",
            f"Затрачено времени : {rep.get('minutes', 0)} мин",
        ]
    except Exception as e:
        lines.append(f"Журнал работ: ошибка ({e})")
    try:
        inventory = ctx.get_service("inventory")
        worst = inventory.worst_hosts(5) if inventory else []
        if worst:
            lines += ["", "Карма парка (худшие):"]
            for w in worst:
                lines.append(f"  {w['name']:<20} карма {w['health_score']}, "
                             f"{'в сети' if w['online'] else 'НЕ В СЕТИ'}")
    except Exception:
        pass
    lines += ["", "Сформировано NetPulse", ""]
    body = "\n".join(lines).encode("utf-8-sig")
    return Response(
        content=body,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="netpulse_otchet_{days}d.txt"'},
    )


@router.get("/report.txt")
async def report_txt(monitor= get_service("monitor")):
    from netpulse import __version__
    snap = monitor.get_snapshot() or {}
    quality = snap.get("quality") or {}
    ping = snap.get("ping") or {}
    quota = monitor.quota_usage()
    lines = [
        "=" * 56,
        f"NETPULSE ОТЧЁТ  ({datetime.now():%Y-%m-%d %H:%M})",
        f"NetPulse {__version__}",
        "=" * 56,
        "",
        f"Качество связи : {quality.get('label')} ({quality.get('score')}/100)",
        f"Скорость       : down {snap.get('down_kbps')} KB/s | up {snap.get('up_kbps')} KB/s",
        f"Пинг           : {ping.get('current')} ms",
        f"Квота день     : {quota.get('daily_used_mb')} MB",
        "",
    ]
    for a in list(monitor.live_alerts or [])[:15]:
        lines.append(f"  [{a.get('timestamp', '')[:19]}] {a.get('type')}: {a.get('message')}")
    body = "\n".join(lines).encode("utf-8")
    return Response(
        content=body,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="netpulse_report.txt"'},
    )
