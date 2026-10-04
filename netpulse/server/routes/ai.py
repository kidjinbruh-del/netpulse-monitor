"""AI routes: статистика, обучение, прогноз."""
import asyncio

from fastapi import APIRouter, Depends

from netpulse.server.dependencies import get_config, get_service

router = APIRouter(prefix="/api", tags=["ai"])


@router.get("/ai")
async def ai_stats(
    monitor= get_service("monitor"),
    ai= get_service("ai"),
    config= Depends(get_config),
):
    cfg_ai = config.ai
    stats = ai.stats()
    pred = await asyncio.to_thread(ai.predict, "speed")
    anomalies = await asyncio.to_thread(ai.anomalies, 15)
    return {
        "enabled": cfg_ai.enabled,
        "threshold": cfg_ai.anomaly_threshold,
        "stats": (stats.get("traffic", {}) if isinstance(stats, dict) else {}),
        "forecast": monitor.forecast_speed(),
        "prediction": {k: v for k, v in pred.items() if k != "timestamp"}
        if isinstance(pred, dict) and "error" not in pred else None,
        "anomalies": list(reversed(anomalies)),
    }


@router.post("/aitrain")
async def ai_train(monitor= get_service("monitor"), ai= get_service("ai")):
    data = await asyncio.to_thread(monitor._training_provider)
    ok = await asyncio.to_thread(ai.train, data) if data and len(data) >= 10 else False
    return {"ok": ok, "samples": len(data or [])}
