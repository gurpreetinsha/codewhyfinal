from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
import time
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

DB_PATH = os.getenv("DATABASE_PATH", "./data/codewhy.sqlite3")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "false").lower() in {"1", "true", "yes", "on"}
OAUTH_CLIENT_ID = os.getenv("GITHUB_OAUTH_CLIENT_ID", "")
OAUTH_CLIENT_SECRET = os.getenv("GITHUB_OAUTH_CLIENT_SECRET", "")
OAUTH_REDIRECT_URI = os.getenv("GITHUB_OAUTH_REDIRECT_URI", "")
SESSION_COOKIE = "codewhy_session"
CSRF_COOKIE = "codewhy_csrf"
SESSION_TTL = 60 * 60 * 12

@contextmanager
def _db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_auth_db() -> None:
    with _db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          github_id INTEGER PRIMARY KEY,
          login TEXT NOT NULL,
          avatar_url TEXT NOT NULL DEFAULT '',
          role TEXT NOT NULL DEFAULT 'developer',
          token_ciphertext TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          session_hash TEXT PRIMARY KEY,
          github_id INTEGER NOT NULL REFERENCES users(github_id) ON DELETE CASCADE,
          csrf_hash TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          github_id INTEGER,
          login TEXT NOT NULL,
          action TEXT NOT NULL,
          resource TEXT NOT NULL DEFAULT '',
          detail TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_events(created_at);
        CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
        """)

def _fernet() -> Fernet:
    if not SESSION_SECRET or len(SESSION_SECRET) < 32:
        raise RuntimeError("SESSION_SECRET must be set to at least 32 characters when GitHub OAuth is enabled.")
    key = base64.urlsafe_b64encode(hashlib.sha256(SESSION_SECRET.encode()).digest())
    return Fernet(key)

def oauth_ready() -> bool:
    return bool(OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET and OAUTH_REDIRECT_URI and len(SESSION_SECRET) >= 32 and not SESSION_SECRET.lower().startswith("replace"))

def encrypt_token(token: str) -> str:
    return _fernet().encrypt(token.encode()).decode() if token else ""

def decrypt_token(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode()).decode()
    except (InvalidToken, RuntimeError):
        return ""

def role_for(login: str) -> str:
    admins = {x.strip().lower() for x in os.getenv("ADMIN_GITHUB_USERS", "").split(",") if x.strip()}
    reviewers = {x.strip().lower() for x in os.getenv("REVIEWER_GITHUB_USERS", "").split(",") if x.strip()}
    if login.lower() in admins:
        return "admin"
    if login.lower() in reviewers:
        return "reviewer"
    return "developer"

def create_session(user: dict[str, Any], access_token: str) -> tuple[str, str]:
    now = int(time.time())
    sid, csrf = secrets.token_urlsafe(36), secrets.token_urlsafe(32)
    session_hash = hashlib.sha256(sid.encode()).hexdigest()
    csrf_hash = hashlib.sha256(csrf.encode()).hexdigest()
    role = role_for(user["login"])
    with _db() as conn:
        conn.execute(
            """INSERT INTO users(github_id,login,avatar_url,role,token_ciphertext,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?) ON CONFLICT(github_id) DO UPDATE SET
            login=excluded.login, avatar_url=excluded.avatar_url, role=excluded.role,
            token_ciphertext=excluded.token_ciphertext, updated_at=excluded.updated_at""",
            (user["id"], user["login"], user.get("avatar_url", ""), role, encrypt_token(access_token), now, now),
        )
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.execute("INSERT INTO sessions(session_hash,github_id,csrf_hash,expires_at,created_at) VALUES(?,?,?,?,?)", (session_hash, user["id"], csrf_hash, now + SESSION_TTL, now))
    return sid, csrf

def get_session(sid: str) -> dict[str, Any] | None:
    if not sid:
        return None
    session_hash = hashlib.sha256(sid.encode()).hexdigest()
    now = int(time.time())
    with _db() as conn:
        row = conn.execute("""SELECT u.github_id,u.login,u.avatar_url,u.role,u.token_ciphertext,s.csrf_hash,s.expires_at
            FROM sessions s JOIN users u ON u.github_id=s.github_id
            WHERE s.session_hash=? AND s.expires_at>?""", (session_hash, now)).fetchone()
    if not row:
        return None
    return {"id": row["github_id"], "login": row["login"], "avatar_url": row["avatar_url"], "role": row["role"], "access_token": decrypt_token(row["token_ciphertext"]), "csrf_hash": row["csrf_hash"], "expires_at": row["expires_at"]}

def delete_session(sid: str) -> None:
    if sid:
        with _db() as conn:
            conn.execute("DELETE FROM sessions WHERE session_hash=?", (hashlib.sha256(sid.encode()).hexdigest(),))

def valid_csrf(session: dict[str, Any], token: str) -> bool:
    return bool(token and hmac.compare_digest(session["csrf_hash"], hashlib.sha256(token.encode()).hexdigest()))

def audit(user: dict[str, Any] | None, action: str, resource: str = "", detail: str = "") -> None:
    with _db() as conn:
        conn.execute("INSERT INTO audit_events(github_id,login,action,resource,detail,created_at) VALUES(?,?,?,?,?,?)",
            (user.get("id") if user else None, user.get("login", "anonymous") if user else "anonymous", action, resource[:300], detail[:500], int(time.time())))

def audit_list(limit: int = 100) -> list[dict[str, Any]]:
    with _db() as conn:
        rows = conn.execute("SELECT login,action,resource,detail,created_at FROM audit_events ORDER BY id DESC LIMIT ?", (min(max(limit, 1), 500),)).fetchall()
    return [dict(row) for row in rows]

def save_investigation(repo_id: str, user_id: int | None, record: dict[str, Any]) -> None:
    with _db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY, repo_id TEXT NOT NULL, user_id INTEGER, payload TEXT NOT NULL, created_at INTEGER NOT NULL
        )""")
        conn.execute("INSERT OR REPLACE INTO investigations(id,repo_id,user_id,payload,created_at) VALUES(?,?,?,?,?)",
            (record["id"], repo_id, user_id, json.dumps(record), record["created_at"]))

def load_investigations(repo_id: str, limit: int = 100) -> list[dict[str, Any]]:
    with _db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY, repo_id TEXT NOT NULL, user_id INTEGER, payload TEXT NOT NULL, created_at INTEGER NOT NULL
        )""")
        rows = conn.execute("SELECT payload FROM investigations WHERE repo_id=? ORDER BY created_at DESC LIMIT ?", (repo_id, limit)).fetchall()
    return [json.loads(row["payload"]) for row in rows]
