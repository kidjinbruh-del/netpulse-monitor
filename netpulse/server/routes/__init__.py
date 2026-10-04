"""Регистрация всех APIRouter в приложении."""
from fastapi import FastAPI

from . import core, auth, special, apps, diagnostics, lan
from . import security, capture, alerts, ai
from . import settings, journal, inventory, runbooks, planner, backupwatch
from . import infra, p2p, map, new_ideas
from . import pages


def register_all_routes(app: FastAPI) -> None:
    # v3 (FastAPI): волны 1-5 — миграция завершена
    app.include_router(core.router)
    app.include_router(auth.router)
    app.include_router(special.router)
    app.include_router(apps.router)
    app.include_router(diagnostics.router)
    app.include_router(lan.router)
    app.include_router(security.router)
    app.include_router(capture.router)
    app.include_router(alerts.router)
    app.include_router(ai.router)
    app.include_router(settings.router)
    app.include_router(journal.router)
    app.include_router(inventory.router)
    app.include_router(runbooks.router)
    app.include_router(planner.router)
    app.include_router(backupwatch.router)
    app.include_router(infra.router)
    app.include_router(p2p.router)
    app.include_router(map.router)
    app.include_router(new_ideas.router)
    app.include_router(pages.router)


__all__ = ["register_all_routes"]
