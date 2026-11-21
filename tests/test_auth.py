import sqlite3

from app import auth


def test_oauth_token_is_encrypted_and_session_is_csrf_protected(tmp_path, monkeypatch):
    database = tmp_path / "auth-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    monkeypatch.delenv("ADMIN_GITHUB_USERS", raising=False)
    monkeypatch.delenv("REVIEWER_GITHUB_USERS", raising=False)
    auth.init_auth_db()

    token = "gho_" + "T" * 48
    sid, csrf = auth.create_session({"id": 987654, "login": "test-developer"}, token)
    session = auth.get_session(sid)

    assert session["access_token"] == token
    assert session["role"] == "developer"
    assert auth.valid_csrf(session, csrf)
    assert not auth.valid_csrf(session, "wrong-token")

    with sqlite3.connect(database) as conn:
        stored = conn.execute("SELECT token_ciphertext FROM users WHERE github_id=987654").fetchone()[0]
    assert token not in stored

    auth.delete_session(sid)
    assert auth.get_session(sid) is None
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE github_id=987654").fetchone()[0] == 0


def test_role_mapping_uses_server_side_allowlists(monkeypatch):
    monkeypatch.setenv("ADMIN_GITHUB_USERS", "owner, security-admin")
    monkeypatch.setenv("REVIEWER_GITHUB_USERS", "reviewer")
    assert auth.role_for("OWNER") == "admin"
    assert auth.role_for("reviewer") == "reviewer"
    assert auth.role_for("someone-else") == "developer"

def test_security_scan_timeline_tracks_new_unchanged_and_resolved_findings(tmp_path, monkeypatch):
    database = tmp_path / "security-history.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    auth.init_auth_db()
    finding = {"fingerprint": "stable-fingerprint", "path": "src/auth.py", "title": "Hard-coded credential", "severity": "critical"}
    first = auth.save_security_scan("alice::org/repo", 42, {"scanned_at": 100, "summary": {"total": 1}, "findings": [finding]})
    second = auth.save_security_scan("alice::org/repo", 42, {"scanned_at": 200, "summary": {"total": 1}, "findings": [finding]})
    third = auth.save_security_scan("alice::org/repo", 42, {"scanned_at": 300, "summary": {"total": 0}, "findings": []})
    assert first["new_count"] == 1
    assert second["unchanged_count"] == 1 and second["new_count"] == 0
    assert third["resolved_count"] == 1
    history = auth.load_security_scans("alice::org/repo")
    assert [item["created_at"] for item in history] == [300, 200, 100]


def test_github_oauth_start_uses_short_lived_browser_state_cookie(monkeypatch):
    from urllib.parse import parse_qs, urlparse
    from fastapi.testclient import TestClient
    from app import main

    monkeypatch.setattr(main, "oauth_ready", lambda: True)
    monkeypatch.setattr(main, "OAUTH_CLIENT_ID", "test-client")
    monkeypatch.setattr(main, "OAUTH_REDIRECT_URI", "https://codewhy.example/api/auth/callback")
    client = TestClient(main.app, follow_redirects=False)

    response = client.get("/api/auth/github")
    assert response.status_code == 302
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    cookie = response.cookies.get(main.OAUTH_STATE_COOKIE)
    assert cookie == state
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "max-age=600" in response.headers["set-cookie"].lower()

    rejected = client.get("/api/auth/callback", params={"code": "fake-code", "state": "attacker-state"})
    assert rejected.status_code == 400
    assert "state" in rejected.json()["detail"].lower()


def test_github_repo_listing_requires_session_and_returns_minimal_repo_data(monkeypatch):
    import asyncio
    from fastapi.testclient import TestClient
    from app import main

    monkeypatch.setattr(main, "AUTH_REQUIRED", False)
    client = TestClient(main.app)
    denied = client.get("/api/github/repos")
    assert denied.status_code == 401

    async def fake_get(url, **kwargs):
        class Response:
            status_code = 200
            def json(self):
                return [{
                    "id": 123, "full_name": "octo/private-project", "name": "private-project",
                    "description": "test", "private": True, "default_branch": "main",
                    "language": "Python", "stargazers_count": 4, "html_url": "https://github.com/octo/private-project",
                    "updated_at": "2026-01-01T00:00:00Z", "permissions": {"push": True, "admin": False}
                }]
        return Response()

    class FakeClient:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        get = fake_get

    monkeypatch.setattr(main.httpx, "AsyncClient", FakeClient)
    client.cookies.set(main.SESSION_COOKIE, "fake-session")
    monkeypatch.setattr(main, "get_session", lambda sid: {
        "id": 1, "login": "octo", "avatar_url": "", "role": "developer",
        "access_token": "token", "csrf_hash": "", "expires_at": 9999999999
    })
    response = client.get("/api/github/repos")
    assert response.status_code == 200
    payload = response.json()
    assert payload["repositories"][0]["full_name"] == "octo/private-project"
    assert payload["repositories"][0]["private"] is True
    assert payload["repositories"][0]["permissions"]["push"] is True
