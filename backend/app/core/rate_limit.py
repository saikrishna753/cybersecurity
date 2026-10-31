"""Simple in-process sliding-window rate limiter (per IP + bucket)."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import get_settings

_lock = Lock()
_windows: dict[str, deque] = defaultdict(deque)


def _prune(key: str, now: float, window: float = 60.0) -> None:
    q = _windows[key]
    while q and now - q[0] > window:
        q.popleft()


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        limit = settings.rate_limit_per_minute
        if limit <= 0 or settings.app_env == "test":
            return await call_next(request)

        # Login endpoint gets a stricter dedicated bucket.
        path = request.url.path
        bucket = "auth" if path.endswith("/auth/login") else "api"
        limit = min(limit, 30) if bucket == "auth" else limit

        ip = request.client.host if request.client else "unknown"
        key = f"{bucket}:{ip}"
        now = time.monotonic()
        with _lock:
            _prune(key, now)
            q = _windows[key]
            if len(q) >= limit:
                return _rate_limited()
            q.append(now)
        return await call_next(request)


def _rate_limited():
    from starlette.responses import JSONResponse

    return JSONResponse(
        {"detail": "Rate limit exceeded"}, status_code=429, headers={"Retry-After": "60"}
    )
