"""Rate limiting + защита от брутфорса токена."""
import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from netpulse.config import Config


class BruteForceProtection:
    """Счётчик неудачных авторизаций: N fails → блок на M секунд."""

    def __init__(self, max_fails: int = 5, block_sec: int = 600):
        self.max_fails = max_fails
        self.block_sec = block_sec
        self._fails: dict = {}
        self._blocked: dict = {}

    def is_blocked(self, ip: str) -> int:
        until = self._blocked.get(ip)
        if until and time.time() < until:
            return int(until - time.time())
        if until:
            self._blocked.pop(ip, None)
        return 0

    def register_fail(self, ip: str) -> bool:
        now = time.time()
        cnt, t0 = self._fails.get(ip, (0, now))
        if now - t0 > self.block_sec:
            cnt, t0 = 0, now
        cnt += 1
        self._fails[ip] = (cnt, t0)
        if cnt >= self.max_fails:
            self._blocked[ip] = now + self.block_sec
            self._fails.pop(ip, None)
            return True
        return False

    def reset(self, ip: str) -> None:
        self._fails.pop(ip, None)
        self._blocked.pop(ip, None)

    def clear(self) -> None:
        self._fails.clear()
        self._blocked.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Простой rate limiter: N запросов в окно W секунд на IP."""

    def __init__(self, app, config: Config):
        super().__init__(app)
        self.config = config
        self._hits: dict = defaultdict(list)
        self.brute_force = BruteForceProtection(
            max_fails=config.security.brute_force_max_fails,
            block_sec=config.security.brute_force_block_sec,
        )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        ip = request.client.host if request.client else "unknown"

        # 1. Брутфорс-блок
        wait = self.brute_force.is_blocked(ip)
        if wait:
            return JSONResponse(
                {"error": f"слишком много неудачных попыток, подождите {wait} c"},
                status_code=429,
            )

        # 2. Rate limit
        now = time.time()
        window = self.config.security.rate_limit_window_sec
        limit = self.config.security.rate_limit_requests
        hits = [t for t in self._hits[ip] if now - t < window]
        hits.append(now)
        self._hits[ip] = hits
        if len(hits) > limit:
            return JSONResponse({"error": "rate limit exceeded"}, status_code=429)

        request.state.brute_force = self.brute_force
        return await call_next(request)
