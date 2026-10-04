"""CORS с allowlist: собственный origin + web_cors_origins из конфига."""
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from netpulse.config import Config


class CORSMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config: Config):
        super().__init__(app)
        self.config = config

    def _allowed_origins(self, request: Request) -> set:
        origins = set()
        host = request.headers.get("host", "")
        if host:
            origins.add(f"http://{host}".rstrip("/"))
            origins.add(f"https://{host}".rstrip("/"))
        for o in (self.config.web.cors_origins or []):
            if isinstance(o, str) and o.strip():
                origins.add(o.strip().rstrip("/"))
        return origins

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        origin = (request.headers.get("origin") or "").strip().rstrip("/")

        if request.method == "OPTIONS":
            # Preflight не требует авторизации
            if origin and origin not in self._allowed_origins(request):
                return Response(status_code=403, content="cors: origin forbidden")
            response = Response(status_code=204)
        else:
            response = await call_next(request)

        if origin and origin in self._allowed_origins(request):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Auth"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response
