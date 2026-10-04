"""BackupWatch routes: статусы и проверка бэкапов."""
import asyncio

from fastapi import APIRouter, Depends, HTTPException

from netpulse.server.dependencies import get_config, get_service

router = APIRouter(prefix="/api", tags=["backupwatch"])


@router.get("/backupstatus")
async def backup_status_list(
    backupwatch= get_service("backupwatch"),
    config= Depends(get_config),
):
    return {"backups": backupwatch.status_list(),
            "enabled": bool(config.backupwatch.enabled)}


@router.post("/backupcheck")
async def backup_check_now(backupwatch= get_service("backupwatch")):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(backupwatch.check_once), timeout=125)
    except asyncio.TimeoutError:
        raise HTTPException(504, "проверка превысила таймаут")
