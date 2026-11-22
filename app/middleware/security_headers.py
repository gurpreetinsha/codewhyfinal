"""
CODEWHY - OWASP Hardened Security Headers Middleware (CORRECTED)
Fixes:
- Added `media-src 'self' data: blob:;` to CSP to allow Sarvam TTS base64 voice playback.
"""
from __future__ import annotations

from typing import Callable, Awaitable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, content_security_policy: str | None = None):
        super().__init__(app)
        self.csp = content_security_policy or (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "media-src 'self' data: blob:; "  # CRITICAL: Allows Sarvam voice TTS audio
            "connect-src 'self' https://api.sarvam.ai https://api.github.com;"
        )

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "microphone=(self)"
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = self.csp
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        return response
