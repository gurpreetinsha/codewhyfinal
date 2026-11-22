"""
CODEWHY - CORS & Origin Hardening (CORRECTED)
Fixes:
- Sets allow_credentials=True with explicit origin matching to support Next.js cookie sessions.
"""
from __future__ import annotations

import os
from fastapi.middleware.cors import CORSMiddleware


def configure_cors_security(app, allowed_origins: list[str] | None = None) -> None:
    configured = allowed_origins or [
        x.strip() for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip()
    ]
    origins = configured if configured else [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000"
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=[
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Retry-After",
            "X-CSRF-Token"
        ]
    )
