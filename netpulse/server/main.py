"""FastAPI application factory: create_app(config, ctx) -> FastAPI."""
from __future__ import annotations
from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from netpulse.server.lifespan import lifespan
from netpulse.server.routes import register_all_routes
from netpulse.server.middleware import setup_middleware
from netpulse.server.static import SPAStaticFiles, web_dir

if TYPE_CHECKING:
    from netpulse.config import Config
    from netpulse.context import AppContext


def create_app(config: "Config", ctx: "AppContext") -> FastAPI:
    from functools import partial
    from netpulse import __version__

    app = FastAPI(
        title="NetPulse API",
        version=__version__,
        lifespan=partial(lifespan, ctx=ctx),
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # Контекст доступен в endpoints через request.app.state
    app.state.ctx = ctx
    app.state.config = config

    # Middleware (порядок: первый в списке — внешний)
    setup_middleware(app, config)

    # API маршруты
    register_all_routes(app)

    # Статика веб-UI + SPA fallback
    directory = web_dir()
    app.mount("/static", StaticFiles(directory=directory), name="static")
    app.mount("/", SPAStaticFiles(directory=directory, html=True), name="spa")

    return app
