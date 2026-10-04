"""Auth/meta routes: whoami, meta, login, selftest, audit."""
import hmac
import sys

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from netpulse.server.dependencies import get_ctx, get_config

router = APIRouter(prefix="/api", tags=["auth"])


class LoginBody(BaseModel):
    token: str = ""


@router.get("/whoami")
async def whoami(request: Request, config= Depends(get_config)):
    user = getattr(request.state, "user", None) or "admin"
    role = getattr(request.state, "role", None) or "admin"
    return {
        "user": user,
        "role": role,
        "auth_enabled": bool(config.web.auth_enabled),
    }


@router.get("/meta")
async def meta(request: Request, config= Depends(get_config), ctx= Depends(get_ctx)):
    from netpulse import __version__
    cfg = config.model_dump(mode="json")
    if cfg.get("web", {}).get("token"):
        cfg["web"]["token"] = "***"
    if isinstance(cfg.get("telegram"), dict) and cfg["telegram"].get("token"):
        cfg["telegram"]["token"] = "***"
    try:
        tables = [r["name"] for r in (
            ctx.db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
                fetch=True,
            ) or []
        )]
    except Exception:
        tables = []
    endpoints = sorted({
        r.path for r in request.app.routes if hasattr(r, "path") and r.path.startswith("/api/")
    })
    modules = {}
    for name in ("journal", "inventory", "watchdog", "runbooks",
                 "backupwatch", "planner", "softwareinv", "wol"):
        mod = sys.modules.get(f"netpulse.{name}")
        if mod:
            modules[name] = (mod.__doc__ or "").strip().split("\n")[0]
    return {
        "app": f"NetPulse {__version__}",
        "endpoints": endpoints,
        "special_paths": ["/api/stream", "/api/rdp", "/api/gposcript",
                          "/journal.txt", "/journal.csv", "/report.txt", "/metrics"],
        "db_tables": tables,
        "config": cfg,
        "modules": modules,
    }


@router.post("/login")
async def login(body: LoginBody, request: Request, config= Depends(get_config)):
    token = (body.token or "").strip()
    candidates = []
    for a in (config.web.admins or []):
        if isinstance(a, dict) and a.get("token"):
            candidates.append((str(a.get("name") or "?"), str(a["token"])))
    if config.web.token:
        candidates.append(("admin", str(config.web.token)))
    for name, tok in candidates:
        if token and hmac.compare_digest(token.encode("utf-8"), tok.encode("utf-8")):
            brute = getattr(request.state, "brute_force", None)
            if brute is not None:
                ip = request.client.host if request.client else "unknown"
                brute.reset(ip)
            resp = JSONResponse({"ok": True, "user": name})
            resp.set_cookie(
                "np_session", token, httponly=True, samesite="strict",
                max_age=315360000, path="/",
            )
            return resp
    brute = getattr(request.state, "brute_force", None)
    if brute is not None:
        ip = request.client.host if request.client else "unknown"
        brute.register_fail(ip)
    return JSONResponse({"ok": False, "error": "неверный токен"}, status_code=401)


@router.get("/audit")
async def audit(limit: int = 100, ctx= Depends(get_ctx)):
    limit = min(max(limit, 1), 500)
    rows = ctx.db.execute(
        """SELECT timestamp, user, ip, action, status, details
           FROM audit_log ORDER BY id DESC LIMIT ?""",
        (limit,), fetch=True,
    ) or []
    return {"entries": rows}


@router.get("/selftest")
async def selftest(ctx= Depends(get_ctx)):
    from netpulse import __version__
    checks = []

    def add(name, ok, info=""):
        checks.append({"name": name, "ok": bool(ok), "info": str(info)[:140]})

    try:
        tables = {r["name"] for r in (ctx.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'", fetch=True) or [])}
        need = {"audit_log"}
        missing = need - tables
        add("БД: таблицы", not missing,
            f"нет: {','.join(sorted(missing))}" if missing else f"{len(tables)} таблиц")
    except Exception as e:
        add("БД", False, e)

    for name in ctx.registry.get_all():
        try:
            svc = ctx.get_service(name)
            h = svc.health()
            add(f"сервис {name}", h.healthy, h.details)
        except Exception as e:
            add(f"сервис {name}", False, e)

    try:
        import shutil
        import os
        free = shutil.disk_usage(os.getcwd()).free
        add("диск", free > 1e9, f"{free / 1e9:.1f} GB свободно")
    except Exception as e:
        add("диск", False, e)

    ok_all = all(c["ok"] for c in checks)
    return {"ok": ok_all, "version": __version__, "checks": checks}


@router.get("/health")
async def health(ctx= Depends(get_ctx)):
    return ctx.health_check()
