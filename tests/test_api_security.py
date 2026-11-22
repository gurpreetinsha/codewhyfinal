"""
Enterprise Unit Tests for API Security, Rate Limiter, Security Headers, and Payload Guard.
"""
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from app.middleware import (
        RateLimiterMiddleware,
        SecurityHeadersMiddleware,
        PayloadGuardMiddleware,
        configure_cors_security
    )
except ImportError:
    from rate_limiter import RateLimiterMiddleware
    from security_headers import SecurityHeadersMiddleware
    from payload_guard import PayloadGuardMiddleware
    from cors_guard import configure_cors_security


def create_test_app():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(PayloadGuardMiddleware, max_json_bytes=100)  # 100 bytes for testing
    app.add_middleware(RateLimiterMiddleware, heavy_limit=2, standard_limit=5, window_seconds=10)
    configure_cors_security(app, allowed_origins=["http://localhost:3000"])

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/test-standard")
    def standard_route():
        return {"status": "ok"}

    @app.post("/api/scan")
    def heavy_route():
        return {"status": "scan_ok"}

    @app.get("/api/admin-route")
    def admin_route(request: Request):
        return {"user": getattr(request.state, "user", None)}

    return app


def test_security_headers_and_csp():
    client = TestClient(create_test_app())
    response = client.get("/api/test-standard")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-XSS-Protection"] == "1; mode=block"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    
    # Critical: media-src 'self' data: blob: for Sarvam TTS audio playback
    csp = response.headers.get("Content-Security-Policy", "")
    assert "media-src 'self' data: blob:;" in csp
    assert "connect-src 'self' https://api.sarvam.ai https://api.github.com;" in csp


def test_rate_limiting_heavy_tier_and_rfc_headers():
    client = TestClient(create_test_app())
    # 2 requests allowed for heavy tier
    r1 = client.post("/api/scan")
    assert r1.status_code == 200
    assert r1.headers["X-RateLimit-Limit"] == "2"
    assert r1.headers["X-RateLimit-Remaining"] == "1"

    r2 = client.post("/api/scan")
    assert r2.status_code == 200
    assert r2.headers["X-RateLimit-Remaining"] == "0"

    # 3rd request must be blocked with 429
    r3 = client.post("/api/scan")
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers
    assert r3.headers["X-RateLimit-Limit"] == "2"
    assert r3.headers["X-RateLimit-Remaining"] == "0"
    data = r3.json()
    assert data["detail"].startswith("Too many requests")
    assert "retry_after_seconds" in data


def test_rate_limit_bypass_for_health():
    client = TestClient(create_test_app())
    # Health checks should never be rate limited
    for _ in range(10):
        res = client.get("/api/health")
        assert res.status_code == 200


def test_payload_size_limit():
    client = TestClient(create_test_app())
    # Sending body larger than 100 bytes limit
    oversized = "x" * 250
    response = client.post("/api/scan", content=oversized, headers={"Content-Length": "250"})
    assert response.status_code == 413
    assert "Payload too large" in response.json()["detail"]


def test_cors_preflight_and_credentials():
    client = TestClient(create_test_app())
    # Preflight OPTIONS
    options_res = client.options(
        "/api/test-standard",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET"
        }
    )
    assert options_res.status_code == 200
    assert options_res.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert options_res.headers.get("access-control-allow-credentials") == "true"

    # Actual GET request exposes rate limit headers
    get_res = client.get("/api/test-standard", headers={"Origin": "http://localhost:3000"})
    assert get_res.status_code == 200
    exposed = get_res.headers.get("access-control-expose-headers", "")
    assert "X-RateLimit-Limit" in exposed
    assert "Retry-After" in exposed
