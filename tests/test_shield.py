import json
import sqlite3
import time
from fastapi.testclient import TestClient

from app import auth
from app import main
from app import shield


def test_security_headers_injected_on_responses(tmp_path, monkeypatch):
    database = tmp_path / "shield-headers-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    auth.init_auth_db()
    shield.init_shield_db()

    client = TestClient(main.app, follow_redirects=False)
    res = client.get("/api/trust-center")
    assert res.status_code == 200

    # Enterprise security headers verified
    headers = res.headers
    assert "max-age=63072000" in headers.get("strict-transport-security", "")
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "camera=()" in headers.get("permissions-policy", "")
    assert "microphone=(self)" in headers.get("permissions-policy", "")
    assert "default-src 'self'" in headers.get("content-security-policy", "")


def test_request_validation_unsupported_methods_rejected(tmp_path, monkeypatch):
    database = tmp_path / "shield-methods-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    auth.init_auth_db()
    shield.init_shield_db()

    client = TestClient(main.app, follow_redirects=False)

    trace_res = client.request("TRACE", "/api/trust-center")
    assert trace_res.status_code == 405
    assert "Method TRACE is not allowed" in trace_res.json()["detail"]

    track_res = client.request("TRACK", "/api/trust-center")
    assert track_res.status_code == 405


def test_request_validation_path_traversal_and_null_bytes(tmp_path, monkeypatch):
    database = tmp_path / "shield-traversal-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    auth.init_auth_db()
    shield.init_shield_db()

    client = TestClient(main.app, follow_redirects=False)

    # Path traversal attempt
    res_trav = client.get("/api/repos/..%2F..%2Fetc%2Fpasswd/overview")
    assert res_trav.status_code == 400
    assert "Malformed request path" in res_trav.json()["detail"]

    # Verify a waf.blocked event was logged in SQLite
    events = shield.list_security_events(event_type="waf.blocked")
    assert len(events) >= 1
    assert events[0]["severity"] in ("medium", "high")


def test_request_validation_payload_size_limit(tmp_path, monkeypatch):
    database = tmp_path / "shield-payload-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    monkeypatch.setattr(main, "MAX_STANDARD_PAYLOAD_BYTES", 500)
    auth.init_auth_db()
    shield.init_shield_db()

    client = TestClient(main.app, follow_redirects=False)

    oversized_data = {"title": "Oversized request title", "description": "D" * 800}
    res = client.post("/api/trust-center/report-vulnerability", json=oversized_data)
    assert res.status_code == 413
    assert "Payload too large" in res.json()["detail"]


def test_request_validation_unsupported_content_type(tmp_path, monkeypatch):
    database = tmp_path / "shield-content-type-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    auth.init_auth_db()
    shield.init_shield_db()

    client = TestClient(main.app, follow_redirects=False)

    res = client.post(
        "/api/trust-center/report-vulnerability",
        content="<xml>malicious</xml>",
        headers={"Content-Type": "application/xml"}
    )
    assert res.status_code == 415
    assert "Unsupported media type" in res.json()["detail"]


def test_persistent_rate_limiting_enforcement(tmp_path, monkeypatch):
    database = tmp_path / "shield-ratelimit-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    auth.init_auth_db()
    shield.init_shield_db()

    # Clear memory cache for clean test
    shield._MEM_RATE_CACHE.clear()

    key = "test-client-ip"
    limit = 3
    window = 10

    # 1. First 3 requests should be allowed
    allowed1, count1, retry1 = shield.check_rate_limit(key, limit=limit, window_seconds=window)
    assert allowed1 is True
    assert count1 == 1
    assert retry1 == 0

    allowed2, count2, retry2 = shield.check_rate_limit(key, limit=limit, window_seconds=window)
    assert allowed2 is True
    assert count2 == 2
    assert retry2 == 0

    allowed3, count3, retry3 = shield.check_rate_limit(key, limit=limit, window_seconds=window)
    assert allowed3 is True
    assert count3 == 3
    assert retry3 == 0

    # 2. 4th request must be rejected
    allowed4, count4, retry4 = shield.check_rate_limit(key, limit=limit, window_seconds=window)
    assert allowed4 is False
    assert retry4 > 0

    # 3. Verify SQLite rate_limit_records table has recorded persistent count
    with sqlite3.connect(database) as conn:
        row = conn.execute("SELECT request_count FROM rate_limit_records WHERE rate_key=?", (key,)).fetchone()
    assert row is not None
    assert row[0] >= 3


def test_security_events_recording_and_admin_api(tmp_path, monkeypatch):
    database = tmp_path / "shield-events-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    monkeypatch.setenv("ADMIN_GITHUB_USERS", "sec-admin")
    auth.init_auth_db()
    shield.init_shield_db()

    # Seed events
    shield.record_security_event("auth.login.success", "info", user={"id": 1, "login": "sec-admin"}, endpoint="/api/auth/github")
    shield.record_security_event("auth.login.failed", "medium", endpoint="/api/auth/github", result="blocked")
    shield.record_security_event("waf.blocked", "high", endpoint="/api/repos/../hack", result="blocked")

    admin_sid, admin_csrf = auth.create_session({"id": 1, "login": "sec-admin", "name": "Sec Admin"}, "token-admin")
    dev_sid, dev_csrf = auth.create_session({"id": 2, "login": "dev-user", "name": "Dev User"}, "token-dev")

    client = TestClient(main.app, follow_redirects=False)

    # 1. Unauthenticated gets 401
    unauth_res = client.get("/api/admin/security/events")
    assert unauth_res.status_code == 401

    # 2. Developer gets 403 Forbidden
    dev_res = client.get("/api/admin/security/events", cookies={auth.SESSION_COOKIE: dev_sid})
    assert dev_res.status_code == 403

    # 3. Admin gets 200 OK
    admin_res = client.get("/api/admin/security/events", cookies={auth.SESSION_COOKIE: admin_sid})
    assert admin_res.status_code == 200
    events = admin_res.json()["events"]
    assert len(events) >= 3

    # 4. Filtering by severity
    high_res = client.get("/api/admin/security/events?severity=high", cookies={auth.SESSION_COOKIE: admin_sid})
    assert high_res.status_code == 200
    high_events = high_res.json()["events"]
    assert all(e["severity"] == "high" for e in high_events)
    assert any(e["event_type"] == "waf.blocked" for e in high_events)

    # 5. Security Stats endpoint
    stats_res = client.get("/api/admin/security/stats", cookies={auth.SESSION_COOKIE: admin_sid})
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["events_24h"] >= 3
    assert stats["blocked_requests_24h"] >= 2
    assert "firewall_status" in stats


def test_incident_management_lifecycle(tmp_path, monkeypatch):
    database = tmp_path / "shield-incidents-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    monkeypatch.setenv("ADMIN_GITHUB_USERS", "sec-admin")
    auth.init_auth_db()
    shield.init_shield_db()

    # Automatic incident triage on critical event
    shield.record_security_event(
        "bruteforce.detected",
        "critical",
        endpoint="/api/auth/github",
        result="blocked",
        detail="Automated credential stuffing cluster observed"
    )

    incidents = shield.list_incidents()
    assert len(incidents) >= 1
    auto_inc = incidents[0]
    assert auto_inc["severity"] == "critical"
    assert "bruteforce.detected" in auto_inc["title"]

    admin_sid, admin_csrf = auth.create_session({"id": 1, "login": "sec-admin", "name": "Sec Admin"}, "token-admin")
    client = TestClient(main.app, follow_redirects=False)

    # Manual incident creation via API
    manual_payload = {
        "title": "Suspicious API access patterns from unknown ASN",
        "description": "High frequency automated calls detected across repository analysis endpoints.",
        "severity": "high",
        "endpoint": "/api/repos/scan"
    }
    create_res = client.post(
        "/api/admin/security/incidents",
        json=manual_payload,
        cookies={auth.SESSION_COOKIE: admin_sid},
        headers={"X-CSRF-Token": admin_csrf}
    )
    assert create_res.status_code in (200, 201)
    manual_inc_id = create_res.json()["incident"]["id"]
    assert manual_inc_id.startswith("INC-")

    # Update incident status: new -> investigating -> contained -> resolved
    for next_status in ["investigating", "contained", "resolved"]:
        patch_res = client.patch(
            f"/api/admin/security/incidents/{manual_inc_id}",
            json={"status": next_status, "resolution_notes": f"Progressed to {next_status}"},
            cookies={auth.SESSION_COOKIE: admin_sid},
            headers={"X-CSRF-Token": admin_csrf}
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["incident"]["status"] == next_status

    # Verify resolved incident details
    resolved_inc = shield.get_incident(manual_inc_id)
    assert resolved_inc["status"] == "resolved"
    assert "resolved" in resolved_inc["resolution_notes"].lower()
    assert resolved_inc["updated_at"] is not None

    # Invalid status rejected
    bad_res = client.patch(
        f"/api/admin/security/incidents/{manual_inc_id}",
        json={"status": "invalid_status"},
        cookies={auth.SESSION_COOKIE: admin_sid},
        headers={"X-CSRF-Token": admin_csrf}
    )
    assert bad_res.status_code == 400


def test_trust_center_and_soc2_endpoints(tmp_path, monkeypatch):
    database = tmp_path / "shield-trust-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    auth.init_auth_db()
    shield.init_shield_db()

    client = TestClient(main.app, follow_redirects=False)

    # 1. Trust Center Public API
    trust_res = client.get("/api/trust-center")
    assert trust_res.status_code == 200
    data = trust_res.json()
    assert len(data["controls"]) == 14
    assert all(c["status"] in ("implemented", "configured") for c in data["controls"])
    assert "architecture_layers" in data
    assert len(data["architecture_layers"]) >= 4
    assert "data_privacy" in data
    assert "external_ai_disclosures" in data["data_privacy"]
    assert "redacted" in data["data_privacy"]["external_ai_disclosures"].lower()

    # 2. SOC 2 Readiness API
    soc2_res = client.get("/api/trust-center/soc2")
    assert soc2_res.status_code == 200
    soc2_data = soc2_res.json()
    assert "SOC 2" in soc2_data["framework"]
    assert len(soc2_data["policies"]) == 12
    policy_ids = [p["policy_id"] for p in soc2_data["policies"]]
    assert "POL-01" in policy_ids
    assert "POL-12" in policy_ids
    assert "controls_evidence_register" in soc2_data

    # 3. Vulnerability Reporting
    report_payload = {
        "title": "Subresource Integrity missing on external CDN asset",
        "description": "Observed external font asset loaded without SRI hash verification.",
        "severity": "low",
        "affected_component": "Frontend CDN Scripts",
        "reporter_contact": "bounty-hunter@example.com",
    }
    vuln_res = client.post("/api/trust-center/report-vulnerability", json=report_payload)
    assert vuln_res.status_code in (200, 201)
    vuln_data = vuln_res.json()
    assert vuln_data["status"] == "received"
    vuln_incident_id = vuln_data["incident_id"]
    assert vuln_incident_id.startswith("INC-")

    # Verify incident was created in database
    inc = shield.get_incident(vuln_incident_id)
    assert inc is not None
    assert report_payload["title"] in inc["title"]
    assert inc["actor"] == "bounty-hunter@example.com"
    assert inc["evidence"]["reporter_contact"] == report_payload["reporter_contact"]
