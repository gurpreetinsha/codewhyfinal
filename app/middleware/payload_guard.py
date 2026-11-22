"""
CODEWHY - Payload Guard & Request Timeout Middleware (CORRECTED)
Fixes:
- Handles chunked transfer encoding / missing Content-Length headers via stream inspection.
"""
from __future__ import annotations

import asyncio
from typing import Callable, Awaitable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse


class PayloadGuardMiddleware(BaseHTTPMiddleware):
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
        is_upload = "/voice/" in path or "/upload" in path
        max_allowed = self.max_upload_bytes if is_upload else self.max_json_bytes

        # 1. Check Content-Length if present
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

        # 2. Intercept streaming / chunked receive to prevent unbounded memory buffering
        total_read = 0
        original_receive = request._receive
        stream_violation = False

        async def guarded_receive():
            nonlocal total_read, stream_violation
            message = await original_receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"")
                total_read += len(chunk)
                if total_read > max_allowed:
                    stream_violation = True
                    # Return empty body to abort further streaming
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        request._receive = guarded_receive

        try:
            response = await asyncio.wait_for(
                call_next(request),
                timeout=self.execution_timeout_seconds
            )
            if stream_violation:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Stream payload exceeded size limit of {max_allowed} bytes."}
                )
            return response
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=504,
                content={
                    "detail": "Request timed out during execution. External service or model response was too slow.",
                    "timeout_seconds": self.execution_timeout_seconds
                }
            )
