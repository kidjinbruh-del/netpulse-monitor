"""Settings/backup routes: чтение и применение конфигурации, бэкапы."""
import asyncio
import os
import uuid
from typing import Any, Dict

from fastapi import APIRouter, Body, Depends, Request

from netpulse.config import PROTECTED_SETTINGS, ConfigLoader
from netpulse.server.dependencies import get_config, get_service

router = APIRouter(prefix="/api", tags=["settings"])


def _masked(config) -> Dict[str, Any]:
    cfg = config.model_dump(mode="json")
    token = (cfg.get("web") or {}).get("token", "")
    if token:
        cfg["web"]["token"] = ""
        cfg["web_token_masked"] = token[:6] + "..." + token[-4:]
    if isinstance(cfg.get("telegram"), dict) and cfg["telegram"].get("token"):
        cfg["telegram"]["token"] = "***"
    cfg.pop("legacy_raw", None)
    return cfg


@router.get("/settings")
async def settings_get(config= Depends(get_config)):
    return _masked(config)


@router.post("/settings")
async def settings_post(
    request: Request,
    body: Dict[str, Any] = Body(default={}),
    monitor= get_service("monitor"),
):
    body = dict(body or {})
    regen = body.pop("_regen_token", False)
    for key in PROTECTED_SETTINGS:
        body.pop(key, None)
    if regen:
        body.setdefault("web_token", uuid.uuid4().hex)
    # Применяем в legacy-ядре (merge + save config.json + live pinger/ai).
    await asyncio.to_thread(monitor.apply_settings, body)
    # Обновляем v3-конфиг в памяти из сохранённого файла.
    try:
        fresh = ConfigLoader("config.json").load()
        request.app.state.config = fresh
        return {"ok": True, "config": _masked(fresh)}
    except Exception:
        return {"ok": True}


@router.post("/backuprun")
async def backup_run(backup= get_service("backup"), config= Depends(get_config)):
    res = await asyncio.to_thread(backup.run_now)
    if res.get("ok"):
        keep = 7
        try:
            keep = int(config.backup.keep)
        except Exception:
            pass
        await asyncio.to_thread(backup.rotate, keep)
    return res


@router.get("/backuplist")
async def backup_list(config= Depends(get_config)):
    d = config.backup.dir or "C:\\Backups"
    try:
        files = sorted(
            (f for f in os.listdir(d) if f.endswith((".rar", ".zip"))),
            reverse=True,
        )[:20]
        out = [
            {"name": f, "size_mb": round(os.path.getsize(os.path.join(d, f)) / 1048576, 1)}
            for f in files
        ]
        return {"backups": out, "dir": d}
    except Exception as e:
        return {"backups": [], "error": str(e)}
