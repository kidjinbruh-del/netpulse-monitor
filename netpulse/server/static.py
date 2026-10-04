"""Статика веб-UI + SPA fallback на index.html."""
import os

from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse


class SPAStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        if response.status_code == 404:
            index = os.path.join(self.directory, "index.html")
            if os.path.isfile(index):
                return FileResponse(index, media_type="text/html; charset=utf-8")
        return response


def web_dir() -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web"
    )
