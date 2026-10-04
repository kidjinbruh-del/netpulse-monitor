"""Diagnostics routes: ping, trace, DNS, speedtest, MTR."""
import asyncio
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from core.tracer import Tracer
from core.utils import decode_process_output, parse_ping_output
from netpulse import __version__
from netpulse.server.dependencies import get_config, get_ctx, get_service

router = APIRouter(prefix="/api", tags=["diagnostics"])

SAFE_TARGET = re.compile(r"^[A-Za-z0-9._\-]{1,253}$")
_tracer = Tracer()


class MtrStartBody(BaseModel):
    target: str = ""
    max_hops: int = 14
    cycle_sec: int = 60


def _check_target(target: str) -> str:
    target = (target or "").strip()
    if not SAFE_TARGET.match(target):
        raise HTTPException(400, "некорректный адрес")
    return target


def _ping_once(target: str) -> dict:
    cmd = (
        ["ping", "-n", "1", "-w", "2000", target]
        if sys.platform == "win32"
        else ["ping", "-c", "1", "-W", "2", target]
    )
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=6,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        out = decode_process_output(proc.stdout + proc.stderr)
        ms, loss = parse_ping_output(out)
        return {"ok": not loss, "ms": ms}
    except Exception:
        return {"ok": False, "ms": None}


@router.get("/ping")
async def ping_probe(
    target: str = Query(""),
    count: int = Query(5, ge=1, le=10),
):
    target = _check_target(target)
    results = await asyncio.gather(*[asyncio.to_thread(_ping_once, target) for _ in range(count)])
    oks = [r["ms"] for r in results if r["ok"]]
    return {
        "target": target,
        "results": list(results),
        "avg_ms": round(sum(oks) / len(oks), 1) if oks else None,
        "loss_pct": round(100 * (count - len(oks)) / count, 1),
    }


@router.get("/trace")
async def trace(target: str = Query(""), max: int = Query(14, ge=1, le=20), ctx= Depends(get_ctx)):
    target = _check_target(target)
    result = await asyncio.to_thread(_tracer.trace, target, max_hops=max)
    try:
        ctx.db.execute(
            """INSERT INTO traces (timestamp, target, hops, avg_ms)
               VALUES (?,?,?,?)""",
            (datetime.now().isoformat(), target,
             result.get("total_hops", 0), result.get("avg_ms", 999)),
        )
    except Exception:
        pass
    return result


@router.get("/traceall")
async def trace_all(config= Depends(get_config)):
    targets = (config.diagnostics.trace_targets or [])[:10]
    if not targets:
        return {}

    async def _one(t):
        try:
            return t, await asyncio.wait_for(asyncio.to_thread(_tracer.trace, t), timeout=120)
        except Exception as e:
            return t, {"error": str(e) or "timeout"}

    return dict(await asyncio.gather(*[_one(t) for t in targets]))


@router.get("/dnsbest")
async def dns_best():
    try:
        return await asyncio.to_thread(_tracer.find_best_dns)
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/dnsresolve")
async def dns_resolve(hosts: str = Query(""), config= Depends(get_config)):
    wanted = [h.strip() for h in hosts.split(",") if h.strip()] or \
        list(config.diagnostics.resolve_hosts or [])
    out = []
    for host in sorted(wanted)[:12]:
        try:
            t0 = time.perf_counter()
            infos = socket.getaddrinfo(host, 443, socket.AF_INET)
            ms = (time.perf_counter() - t0) * 1000
            ip = infos[0][4][0] if infos else "?"
            out.append({"host": host, "ip": ip, "ms": round(ms, 1)})
        except Exception:
            out.append({"host": host, "ip": None, "ms": None})
    return {"results": out}


def _speedtest_down(url: str, nbytes: int, timeout: int) -> dict:
    from urllib.request import Request, urlopen
    t0 = time.perf_counter()
    received = 0
    req = Request(url, headers={"User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetPulse/" + __version__})
    with urlopen(req, timeout=timeout) as resp:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            received += len(chunk)
            if time.perf_counter() - t0 > timeout:
                break
    elapsed = max(time.perf_counter() - t0, 1e-6)
    mbps = received * 8 / elapsed / 1e6
    return {"bytes": received, "seconds": round(elapsed, 2), "mbps": round(mbps, 2)}


@router.get("/speedtest")
async def speedtest(
    bytes: int = Query(0, ge=0, le=64_000_000),
    config= Depends(get_config),
    ctx= Depends(get_ctx),
):
    st = config.speedtest
    nbytes = bytes or st.bytes_down
    try:
        url = st.url_down.format(bytes=nbytes)
    except Exception:
        url = st.url_down
    _check_url(url)
    res = await asyncio.to_thread(_speedtest_down, url, nbytes, st.timeout_sec)
    try:
        ctx.db.execute(
            """INSERT INTO speedtest_log (timestamp, mbps, direction, bytes)
               VALUES (?,?,?,?)""",
            (datetime.now().isoformat(), res["mbps"], "down", res["bytes"]),
        )
    except Exception:
        pass
    return res


def _check_url(url: str) -> None:
    try:
        parts = urlparse(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError()
    except Exception:
        raise HTTPException(400, "некорректный URL speedtest в конфиге")


def _speedtest_up(url: str, nbytes: int, timeout: int) -> dict:
    from urllib.request import Request, urlopen
    payload = b"x" * 65536
    t0 = time.perf_counter()
    sent = 0
    try:
        while sent < nbytes and time.perf_counter() - t0 < timeout:
            req = Request(url, data=payload, method="POST",
                          headers={"User-Agent":
                              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetPulse/" + __version__})
            urlopen(req, timeout=10).read(64)
            sent += len(payload)
    except Exception:
        pass
    elapsed = max(time.perf_counter() - t0, 1e-6)
    mbps = sent * 8 / elapsed / 1e6
    return {"bytes": sent, "seconds": round(elapsed, 2),
            "mbps": round(mbps, 2), "note": "оценочно при успешных ответах"}


@router.get("/uploadtest")
async def uploadtest(
    bytes: int = Query(0, ge=0, le=16_000_000),
    config= Depends(get_config),
    ctx= Depends(get_ctx),
):
    st = config.speedtest
    nbytes = bytes or 2_000_000
    if not st.url_up:
        raise HTTPException(400, "URL upload-теста не настроен (speedtest.url_up)")
    _check_url(st.url_up)
    res = await asyncio.to_thread(_speedtest_up, st.url_up, nbytes, st.timeout_sec)
    try:
        ctx.db.execute(
            """INSERT INTO speedtest_log (timestamp, mbps, direction, bytes)
               VALUES (?,?,?,?)""",
            (datetime.now().isoformat(), res["mbps"], "up", res["bytes"]),
        )
    except Exception:
        pass
    return res


@router.get("/speedlog")
async def speedtest_log(ctx= Depends(get_ctx)):
    try:
        rows = ctx.db.execute(
            """SELECT timestamp, mbps, direction FROM speedtest_log
               ORDER BY id DESC LIMIT 30""", fetch=True) or []
    except Exception:
        rows = []
    return {"log": rows}


def _require_mtr(monitor):
    mtr = monitor.mtr
    if mtr is None:
        raise HTTPException(503, "MTR-движок недоступен (monitor backend degraded)")
    return mtr


@router.get("/mtrstats")
async def mtr_stats(monitor= get_service("monitor")):
    return await asyncio.to_thread(_require_mtr(monitor).stats)


@router.post("/mtrstart")
async def mtr_start(body: MtrStartBody, monitor= get_service("monitor")):
    mtr = _require_mtr(monitor)
    await asyncio.to_thread(
        mtr.start, body.target or None, body.max_hops, body.cycle_sec
    )
    return {"ok": True}


@router.post("/mtrstop")
async def mtr_stop(monitor= get_service("monitor")):
    mtr = _require_mtr(monitor)
    await asyncio.to_thread(mtr.stop)
    return {"ok": True}
