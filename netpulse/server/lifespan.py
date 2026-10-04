"""FastAPI lifespan: связывает жизненный цикл приложения с AppContext."""
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI

if TYPE_CHECKING:
    from netpulse.context import AppContext


@asynccontextmanager
async def lifespan(app: FastAPI, ctx: "AppContext"):
    """Startup → ctx.startup(), shutdown → ctx.shutdown()."""
    ctx.startup()
    app.state.ctx = ctx
    try:
        yield
    finally:
        ctx.shutdown()
