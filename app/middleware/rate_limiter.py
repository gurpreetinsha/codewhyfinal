"""
CODEWHY - Tiered Sliding-Window Rate Limiter Middleware (CORRECTED)
Fixes:
1. Fallback session resolution: Directly reads session cookie so authenticated
   roles (Admin 5x, Developer 1.5x) are never lost due to middleware ordering.
2. Memory Leak Fix: Periodically sweeps dead/stale IP buckets from RAM.
3. RFC 6585 Compliant Headers on both 200 and 429 responses.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Callable, Awaitable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse


class TieredRateLimiter:
    """
    In-memory Sliding Window Rate Limiter with automatic memory leak prevention.
    """
    def __init__(self, window_seconds: int = 60, max_keys: int = 10000):
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.buckets: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.time()

    def _cleanup_stale_buckets(self, now: float) -> None:
        """Purges stale IP entries older than the sliding window to prevent memory leaks."""
        if now - self._last_cleanup < 60 and len(self.buckets) < self.max_keys:
            return
        self._last_cleanup = now
        cutoff = now - self.window_seconds
        stale = [k for k, stamps in self.buckets.items() if not stamps or stamps[-1] <= cutoff]
        for k in stale:
            del self.buckets[k]

    def _prune(self, key: str, now: float) -> list[float]:
        cutoff = now - self.window_seconds
        valid_stamps = [ts for ts in self.buckets[key] if ts > cutoff]
        self.buckets[key] = valid_stamps
        return valid_stamps

    def check(self, key: str, limit: int) -> tuple[bool, int, int]:
        now = time.time()
        self._cleanup_stale_buckets(now)
        stamps = self._prune(key, now)
        current_count = len(stamps)

        oldest = stamps[0] if stamps else now
        reset_seconds = max(1, int(self.window_seconds - (now - oldest)))

        if current_count >= limit:
            return False, 0, reset_seconds

        stamps.append(now)
        remaining = max(0, limit - len(stamps))
        return True, remaining, reset_seconds


class RateLimiterMiddleware(BaseHTTPMiddleware):
    EXPENSIVE_PATHS = {
        "/scan",
        "/investigate",
        "/impact",
        "/change-simulate",
        "/pull-request/review",
        "/voice/"
    }

    BYPASS_PATHS = {
        "/api/health",
        "/api/auth/status",
        "/docs",
        "/openapi.json",
        "/redoc"
    }

    def __init__(
        self,
        app,
        heavy_limit: int = 10,
        standard_limit: int = 60,
        window_seconds: int = 60
    ):
        super().__init__(app)
        self.limiter = TieredRateLimiter(window_seconds=window_seconds)
        self.heavy_limit = heavy_limit
        self.standard_limit = standard_limit

    def _resolve_limit_and_key(self, request: Request) -> tuple[str, int, bool]:
        path = request.url.path
        if any(path == b or path.startswith(b) for b in self.BYPASS_PATHS):
            return "bypass", 9999, True

        is_heavy = any(x in path for x in self.EXPENSIVE_PATHS)
        base_limit = self.heavy_limit if is_heavy else self.standard_limit

        # 1. Resolve User (State or Direct Session Cookie Fallback)
        user = getattr(request.state, "user", None)
        if not user:
            sid = request.cookies.get("codewhy_session", "")
            if sid:
                try:
                    from app.auth import get_session
                    user = get_session(sid)
                    request.state.user = user
                except Exception:
                    pass

        # 2. Resolve Client IP
        client_ip = request.client.host if request.client else "unknown"
        x_forwarded = request.headers.get("X-Forwarded-For")
        if x_forwarded:
            client_ip = x_forwarded.split(",")[0].strip()

        tier_tag = "heavy" if is_heavy else "standard"

        if user and isinstance(user, dict):
            role = str(user.get("role", "developer")).lower()
            if role == "admin":
                limit = base_limit * 5  # 5x quota for Admin
            elif role in {"reviewer", "developer"}:
                limit = int(base_limit * 1.5)  # 1.5x quota for registered developers
            else:
                limit = base_limit
            key = f"user:{user.get('id', client_ip)}:{tier_tag}"
        else:
            limit = base_limit
            key = f"ip:{client_ip}:{tier_tag}"

        return key, limit, False

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        key, limit, bypass = self._resolve_limit_and_key(request)

        if bypass:
            return await call_next(request)

        allowed, remaining, reset_seconds = self.limiter.check(key, limit)

        if not allowed:
            headers = {
                "Retry-After": str(reset_seconds),
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_seconds),
            }
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please slow down and try again later.",
                    "retry_after_seconds": reset_seconds,
                    "tier": key.split(":")[-1]
                },
                headers=headers
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_seconds)
        return response
