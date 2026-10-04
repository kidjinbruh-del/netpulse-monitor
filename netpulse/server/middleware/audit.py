"""Audit middleware: логирует все мутирующие POST-запросы в audit_log."""
import json
import re

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method != "POST" or not request.url.path.startswith("/api/"):
            return await call_next(request)

        try:
            body = await request.json()
        except Exception:
            body = {}
        # Маскируем секреты
        try:
            details = json.dumps(body, ensure_ascii=False)[:400]
            for secret in ("token", "web_token"):
                details = re.sub(
                    rf'"{secret}"\s*:\s*"[^"]*"', f'"{secret}": "***"', details
                )
        except Exception:
            details = "{}"

        response = await call_next(request)

        try:
            ctx = request.app.state.ctx
            user = getattr(request.state, "user", "admin")
            ip = request.client.host if request.client else "unknown"
            request_id = getattr(request.state, "request_id", None)
            ctx.db.execute(
                """INSERT INTO audit_log
                   (timestamp, user, ip, action, status, details, request_id)
                   VALUES (datetime('now','localtime'),?,?,?,?,?,?)""",
                (
                    user, ip,
                    request.url.path[len("/api/"):],
                    response.status_code, details, request_id,
                ),
            )
        except Exception:
            pass
        return response
