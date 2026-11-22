"""
CODEWHY - OWASP Hardened Security Headers Middleware
Protects the platform against XSS, clickjacking, MIME-sniffing, and cross-site framing.
"""
from __future__ import annotations

from typing import Callable, Awaitable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects OWASP-recommended HTTP security response headers into every request.
    """
    def __init__(self, app, content_security_policy: str | None = None):
        super().__init__(app)
        self.csp = content_security_policy or (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://api.sarvam.ai https://api.github.com;"
        )

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)

        # 1. Prevent MIME-Type Confusion Attacks
        response.headers["X-Content-Type-Options"] = "nosniff"

        # 2. Anti-Clickjacking: Disallow loading CODEWHY inside foreign iframes
        response.headers["X-Frame-Options"] = "DENY"

        # 3. Enable legacy browser XSS filtering
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # 4. Strict Referrer Policy: Send full URL for same-origin, domain-only cross-origin
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 5. Microphone Policy: Allow microphone strictly on origin domain (for voice features)
        response.headers["Permissions-Policy"] = "microphone=(self)"

        # 6. Content Security Policy (CSP)
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = self.csp

        # 7. Cross-Origin Resource Policy
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        return response
