import sqlite3
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from app import auth
from app import main


def test_oauth_token_is_encrypted_and_session_is_csrf_protected(tmp_path, monkeypatch):
    database = tmp_path / "auth-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    monkeypatch.delenv("ADMIN_GITHUB_USERS", raising=False)
    monkeypatch.delenv("REVIEWER_GITHUB_USERS", raising=False)
    auth.init_auth_db()

    token = "gho_" + "T" * 48
    sid, csrf = auth.create_session({"id": 987654, "login": "test-developer", "name": "Dev User"}, token)
    session = auth.get_session(sid)

    assert session["access_token"] == token
    assert session["role"] == "developer"
    assert session["status"] == "active"
    assert session["has_token"] is True
    assert auth.valid_csrf(session, csrf)
    assert not auth.valid_csrf(session, "wrong-token")

    with sqlite3.connect(database) as conn:
        stored = conn.execute("SELECT token_ciphertext FROM users WHERE github_id=987654").fetchone()[0]
    assert token not in stored

    # Logging out terminates the session but preserves the registered user account
    auth.delete_session(sid)
    assert auth.get_session(sid) is None
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE github_id=987654").fetchone()[0] == 1


def test_user_persistence_and_role_preservation(tmp_path, monkeypatch):
    database = tmp_path / "persist-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    auth.init_auth_db()

    # Initial registration: default role 'developer'
    user1 = auth.create_or_update_user({"id": 112233, "login": "alice", "name": "Alice Developer"}, "token-1")
    assert user1["role"] == "developer"
    assert user1["status"] == "active"

    # Admin updates Alice's role to 'reviewer'
    auth.update_user_role(112233, "reviewer", admin_user={"id": 999999, "login": "admin-bob"})

    # Alice logs in again next day: assigned role 'reviewer' is preserved!
    user2 = auth.create_or_update_user({"id": 112233, "login": "alice", "name": "Alice Developer Updated"}, "token-2")
    assert user2["role"] == "reviewer"
    assert user2["name"] == "Alice Developer Updated"

    fetched = auth.get_user(112233)
    assert fetched["role"] == "reviewer"


def test_role_mapping_uses_server_side_allowlists(monkeypatch):
    monkeypatch.setenv("ADMIN_GITHUB_USERS", "owner, security-admin")
    monkeypatch.setenv("REVIEWER_GITHUB_USERS", "reviewer")
    assert auth.role_for("OWNER") == "admin"
    assert auth.role_for("reviewer") == "reviewer"
    assert auth.role_for("someone-else") == "developer"


def test_disconnect_user_clears_token_and_sessions(tmp_path, monkeypatch):
    database = tmp_path / "disconnect-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    auth.init_auth_db()

    sid, _ = auth.create_session({"id": 445566, "login": "charlie"}, "github-token-secret")
    assert auth.get_session(sid) is not None

    # Disconnect GitHub account
    auth.disconnect_user(445566)

    # Active session must be revoked
    assert auth.get_session(sid) is None

    # Stored token must be deleted from DB
    user = auth.get_user(445566)
    assert user["has_token"] is False
    with sqlite3.connect(database) as conn:
        token_cipher = conn.execute("SELECT token_ciphertext FROM users WHERE github_id=445566").fetchone()[0]
        assert token_cipher in (None, "")


def test_github_oauth_start_and_error_handling(monkeypatch):
    monkeypatch.setattr(main, "oauth_ready", lambda: True)
    monkeypatch.setattr(main, "OAUTH_CLIENT_ID", "test-client")
    monkeypatch.setattr(main, "OAUTH_REDIRECT_URI", "https://codewhy.example/api/auth/callback")
    client = TestClient(main.app, follow_redirects=False)

    # 1. Start OAuth flow
    response = client.get("/api/auth/github")
    assert response.status_code == 302
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    cookie = response.cookies.get(main.OAUTH_STATE_COOKIE)
    assert cookie == state
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "max-age=600" in response.headers["set-cookie"].lower()

    # 2. State mismatch triggers secure redirect with error notice
    rejected = client.get("/api/auth/callback", params={"code": "fake-code", "state": "attacker-state"})
    assert rejected.status_code == 302
    assert "auth_error" in rejected.headers["location"]

    # 3. User cancellation triggers secure redirect with error notice
    cancelled = client.get("/api/auth/callback", params={"error": "access_denied", "error_description": "User cancelled authorization"})
    assert cancelled.status_code == 302
    assert "auth_error" in cancelled.headers["location"]


def test_rbac_admin_and_role_management(tmp_path, monkeypatch):
    database = tmp_path / "rbac-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    monkeypatch.setenv("ADMIN_GITHUB_USERS", "root-admin")
    auth.init_auth_db()

    # Create admin user and session
    admin_sid, admin_csrf = auth.create_session({"id": 1001, "login": "root-admin", "name": "Root Admin"}, "token-admin")
    # Create developer user and session
    dev_sid, dev_csrf = auth.create_session({"id": 1002, "login": "coder", "name": "Coder User"}, "token-dev")

    client = TestClient(main.app, follow_redirects=False)

    # 1. Any authenticated user can access user list (200 OK)
    dev_res = client.get("/api/admin/users", cookies={auth.SESSION_COOKIE: dev_sid})
    assert dev_res.status_code == 200
    user_logins = [u["login"] for u in dev_res.json()["users"]]
    assert "root-admin" in user_logins
    assert "coder" in user_logins

    # 3. Admin can update developer role to reviewer
    update_res = client.patch(
        "/api/admin/users/1002/role",
        json={"role": "reviewer"},
        cookies={auth.SESSION_COOKIE: admin_sid},
        headers={"X-CSRF-Token": admin_csrf}
    )
    assert update_res.status_code == 200
    assert update_res.json()["user"]["new_role"] == "reviewer"

    # 4. Self-demotion prevention: Admin cannot demote themselves
    self_demote = client.patch(
        "/api/admin/users/1001/role",
        json={"role": "developer"},
        cookies={auth.SESSION_COOKIE: admin_sid},
        headers={"X-CSRF-Token": admin_csrf}
    )
    assert self_demote.status_code == 400
    assert "demote" in self_demote.json()["detail"].lower()

    # 5. Self-suspension prevention: Admin cannot suspend themselves
    self_suspend = client.patch(
        "/api/admin/users/1001/status",
        json={"status": "suspended"},
        cookies={auth.SESSION_COOKIE: admin_sid},
        headers={"X-CSRF-Token": admin_csrf}
    )
    assert self_suspend.status_code == 400
    assert "suspend" in self_suspend.json()["detail"].lower()

    # 6. Admin can suspend developer
    suspend_res = client.patch(
        "/api/admin/users/1002/status",
        json={"status": "suspended"},
        cookies={auth.SESSION_COOKIE: admin_sid},
        headers={"X-CSRF-Token": admin_csrf}
    )
    assert suspend_res.status_code == 200
    assert suspend_res.json()["user"]["new_status"] == "suspended"

    # 7. Suspended user sessions are revoked; access is denied (401/403)
    suspended_res = client.get("/api/admin/users", cookies={auth.SESSION_COOKIE: dev_sid})
    assert suspended_res.status_code in (401, 403)


def test_rbac_pr_risk_reviewer_permission(tmp_path, monkeypatch):
    database = tmp_path / "rbac-pr-test.sqlite3"
    monkeypatch.setattr(auth, "DB_PATH", str(database))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-secret-" + "x" * 48)
    auth.init_auth_db()

    # Register developer and reviewer
    dev_sid, dev_csrf = auth.create_session({"id": 2001, "login": "dev1"}, "tok1")
    rev_sid, rev_csrf = auth.create_session({"id": 2002, "login": "rev1"}, "tok2")
    auth.update_user_role(2002, "reviewer", admin_user={"id": 9999, "login": "admin"})

    client = TestClient(main.app, follow_redirects=False)

    pr_payload = {
        "url": "https://github.com/atlas-commerce/demo/pull/42"
    }

    # Load demo repo under developer's account
    dev_demo = client.get("/api/demo", cookies={auth.SESSION_COOKIE: dev_sid})
    dev_repo_id = dev_demo.json()["id"]

    # All users can review PRs (does not get 403 Forbidden)
    dev_pr = client.post(
        f"/api/repos/{dev_repo_id}/pull-request/review",
        json=pr_payload,
        cookies={auth.SESSION_COOKIE: dev_sid},
        headers={"X-CSRF-Token": dev_csrf}
    )
    assert dev_pr.status_code != 403

    # Load demo repo under reviewer's account
    rev_demo = client.get("/api/demo", cookies={auth.SESSION_COOKIE: rev_sid})
    rev_repo_id = rev_demo.json()["id"]

    # Reviewer passes RBAC authorization check (does not get 403 Forbidden)
    rev_pr = client.post(
        f"/api/repos/{rev_repo_id}/pull-request/review",
        json=pr_payload,
        cookies={auth.SESSION_COOKIE: rev_sid},
        headers={"X-CSRF-Token": rev_csrf}
    )
    assert rev_pr.status_code != 403


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
    assert rejected.status_code in (302, 400)
    if rejected.status_code == 400:
        assert "state" in rejected.json()["detail"].lower()
    else:
        assert "auth_error" in rejected.headers.get("location", "").lower()


def test_github_repo_listing_requires_session_and_returns_minimal_repo_data(monkeypatch):
    import asyncio
    from fastapi.testclient import TestClient
    from app import main

    monkeypatch.setattr(main, "AUTH_REQUIRED", False)
    client = TestClient(main.app)
    denied = client.get("/api/github/repos")
    assert denied.status_code == 401

    async def fake_get(self, url, **kwargs):
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
