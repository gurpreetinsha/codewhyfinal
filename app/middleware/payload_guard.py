"""
CODEWHY - Payload Guard & Request Timeout Middleware
Defends against Denial-of-Service (DoS) memory exhaustion and hanging requests.
"""
from __future__ import annotations

import asyncio
from typing import Callable, Awaitable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse


class PayloadGuardMiddleware(BaseHTTPMiddleware):
    """
    Enforces payload size limits before buffering into memory:
    - Default JSON / Diff payloads: Max 2 MB
    - Voice Audio uploads: Max 15 MB
    - Execution Timeout: Max 60 seconds (prevents hanging LLM or external calls)
    """
    def __init__(
        self,
        app,
        max_json_bytes: int = 2 * 1024 * 1024,      # 2 MB
        max_upload_bytes: int = 15 * 1024 * 1024,    # 15 MB
        execution_timeout_seconds: float = 60.0
    ):
        super().__init__(app)
        self.max_json_bytes = max_json_bytes
        self.max_upload_bytes = max_upload_bytes
        self.execution_timeout_seconds = execution_timeout_seconds

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        path = request.url.path

        # Determine limit for path
        is_upload = "/voice/" in path or "/upload" in path
        max_allowed = self.max_upload_bytes if is_upload else self.max_json_bytes

        # Inspect Content-Length header BEFORE body read
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                if length > max_allowed:
                    limit_mb = max_allowed / (1024 * 1024)
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": f"Payload too large. Max permitted is {limit_mb:.1f} MB for this endpoint.",
                            "limit_bytes": max_allowed,
                            "received_bytes": length
                        }
                    )
            except ValueError:
                pass

        # Execution Timeout Guard (60s)
        try:
            return await asyncio.wait_for(
                call_next(request),
                timeout=self.execution_timeout_seconds
            )
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=504,
                content={
                    "detail": "Request timed out during execution. External service or model response was too slow.",
                    "timeout_seconds": self.execution_timeout_seconds
                }
            )
