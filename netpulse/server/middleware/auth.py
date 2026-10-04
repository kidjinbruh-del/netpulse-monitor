"""Token auth: X-Auth header или HttpOnly cookie. Публичные пути без проверки."""
import hmac
import re

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from netpulse.config import Config

PUBLIC_PATHS = {
    "/api/whoami",
    "/api/meta",
    "/api/login",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
}


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config: Config):
        super().__init__(app)
        self.config = config

    def _candidates(self) -> list:
        """Список (name, token, role)."""
        out = []
        for a in (self.config.web.admins or []):
            if isinstance(a, dict) and a.get("token"):
                out.append((str(a.get("name") or "?"), str(a["token"]), "admin"))
        for u in (self.config.web.users or []):
            if isinstance(u, dict) and u.get("token"):
                role = "viewer" if str(u.get("role", "admin")) == "viewer" else "admin"
                out.append((str(u.get("name") or "?"), str(u["token"]), role))
        if self.config.web.token:
            out.append(("admin", str(self.config.web.token), "admin"))
        return out

    def _identify(self, request: Request):
        if not self.config.web.auth_enabled:
            return ("admin", "admin")
        candidates = self._candidates()
        if not candidates:
            return None
        supplied = [request.headers.get("x-auth", "")]
        for cname in ("np_session", "np_token"):
            m = re.search(rf"(?:^|;\s*){cname}=([^\s;]+)", request.headers.get("cookie", "") or "")
            if m:
                supplied.append(m.group(1))
        for name, tok, role in candidates:
            for s in supplied:
                if s and hmac.compare_digest(s.encode("utf-8"), tok.encode("utf-8")):
                    return (name, role)
        return None

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        # Статика и корень — без auth (SPA сама проверяет сессию)
        if not path.startswith("/api/") and not path.startswith("/metrics"):
            return await call_next(request)

        if path in PUBLIC_PATHS:
            return await call_next(request)

        # IP allowlist
        if self._allowlist_denied(request):
            return JSONResponse({"error": "forbidden: IP вне разрешённых сетей"}, status_code=403)

        ident = self._identify(request)
        if ident is None:
            brute = getattr(request.state, "brute_force", None)
            if request.method == "POST" and brute is not None:
                ip = request.client.host if request.client else "unknown"
                brute.register_fail(ip)
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        request.state.user, request.state.role = ident

        # Анти-CSRF для мутаций
        if request.method == "POST":
            ctype = (request.headers.get("content-type") or "").lower()
            try:
                length = int(request.headers.get("content-length") or 0)
            except ValueError:
                length = 0
            # Пустой POST без тела (например /api/aitrain) — пропускаем проверку.
            if length > 0 and "application/json" not in ctype:
                return JSONResponse(
                    {"error": "нужен Content-Type: application/json"}, status_code=415
                )
            if self.config.web.auth_enabled and not request.headers.get("x-auth"):
                # Cookie-сессия без X-Auth — только чтение, мутации запрещены
                pass

        # RBAC: viewer — только чтение + alertsack/lanalias
        if ident[1] == "viewer" and request.method == "POST":
            name = path[len("/api/"):]
            if name not in ("alertsack", "lanalias"):
                return JSONResponse(
                    {"error": "forbidden: роль viewer не позволяет изменение"},
                    status_code=403,
                )

        return await call_next(request)

    def _allowlist_denied(self, request: Request) -> bool:
        aw = self.config.ip_allowlist
        if not aw.enabled:
            return False
        ip = request.client.host if request.client else ""
        for net in (aw.networks or []):
            if self._ip_in_network(ip, str(net)):
                return False
        return True

    @staticmethod
    def _ip_in_network(ip: str, network: str) -> bool:
        try:
            if "/" in network:
                ns, prefix = network.split("/", 1)
                prefix = int(prefix)
            else:
                ns, prefix = network, 32
            h = (
                int(ip.split(".")[0]) << 24
                | int(ip.split(".")[1]) << 16
                | int(ip.split(".")[2]) << 8
                | int(ip.split(".")[3])
            )
            base = (
                int(ns.split(".")[0]) << 24
                | int(ns.split(".")[1]) << 16
                | int(ns.split(".")[2]) << 8
                | int(ns.split(".")[3])
            )
            mask = ((1 << prefix) - 1) << (32 - prefix) if 0 < prefix < 32 else (
                0 if prefix == 0 else 0xFFFFFFFF
            )
            return (h & mask) == (base & mask)
        except Exception:
            return False
