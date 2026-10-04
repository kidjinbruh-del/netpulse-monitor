from .request_id import RequestIDMiddleware
from .security import SecurityHeadersMiddleware
from .cors import CORSMiddleware
from .auth import AuthMiddleware
from .audit import AuditMiddleware
from .rate_limit import RateLimitMiddleware, BruteForceProtection


def setup_middleware(app, config):
    """Подключает middleware в правильном порядке (первый в списке — внешний)."""
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CORSMiddleware, config=config)
    app.add_middleware(RateLimitMiddleware, config=config)
    app.add_middleware(AuthMiddleware, config=config)
    app.add_middleware(AuditMiddleware)


__all__ = [
    "setup_middleware",
    "RequestIDMiddleware",
    "SecurityHeadersMiddleware",
    "CORSMiddleware",
    "AuthMiddleware",
    "AuditMiddleware",
    "RateLimitMiddleware",
    "BruteForceProtection",
]
