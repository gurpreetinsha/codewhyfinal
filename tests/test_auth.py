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
