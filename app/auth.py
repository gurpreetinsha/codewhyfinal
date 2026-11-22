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

_configured_db_path = os.getenv("DATABASE_PATH", "")
# Vercel Functions have a read-only deployment filesystem; only /tmp is writable.
# SQLite in /tmp is suitable for a demo, but is ephemeral and not shared across instances.
DB_PATH = (
    _configured_db_path if _configured_db_path.startswith("/tmp/")
    else "/tmp/codewhy.sqlite3"
) if os.getenv("VERCEL") else (_configured_db_path or "./data/codewhy.sqlite3")
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
          name TEXT NOT NULL DEFAULT '',
          avatar_url TEXT NOT NULL DEFAULT '',
          role TEXT NOT NULL DEFAULT 'developer',
          status TEXT NOT NULL DEFAULT 'active',
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
        CREATE TABLE IF NOT EXISTS security_scans (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          repo_id TEXT NOT NULL,
          user_id INTEGER,
          created_at INTEGER NOT NULL,
          summary_json TEXT NOT NULL,
          findings_json TEXT NOT NULL,
          delta_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS security_scans_repo_idx ON security_scans(repo_id, created_at);
        CREATE TABLE IF NOT EXISTS sentinel_investigations (
          id TEXT PRIMARY KEY,
          repo_id TEXT NOT NULL,
          user_id INTEGER,
          question TEXT NOT NULL,
          original_transcript TEXT DEFAULT '',
          language_code TEXT NOT NULL DEFAULT 'en-IN',
          interpreted_query TEXT NOT NULL DEFAULT '',
          findings_json TEXT NOT NULL DEFAULT '[]',
          attack_paths_json TEXT NOT NULL DEFAULT '[]',
          graph_entities_json TEXT NOT NULL DEFAULT '{}',
          evidence_json TEXT NOT NULL DEFAULT '[]',
          report_markdown TEXT NOT NULL DEFAULT '',
          remediation_json TEXT NOT NULL DEFAULT '[]',
          audio_base64 TEXT DEFAULT '',
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS sentinel_repo_idx ON sentinel_investigations(repo_id, created_at);
        CREATE TABLE IF NOT EXISTS sentinel_finding_statuses (
          finding_id TEXT PRIMARY KEY,
          repo_id TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'open',
          notes TEXT DEFAULT '',
          updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS sentinel_finding_repo_idx ON sentinel_finding_statuses(repo_id);
        """)
        # Safe migrations for existing databases
        for col in ["name TEXT NOT NULL DEFAULT ''", "status TEXT NOT NULL DEFAULT 'active'"]:
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass
        now = int(time.time())
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))

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

def create_or_update_user(user: dict[str, Any], access_token: str) -> dict[str, Any]:
    now = int(time.time())
    github_id = user["id"]
    login = user["login"]
    name = user.get("name") or user.get("login") or ""
    avatar_url = user.get("avatar_url", "")
    token_cipher = encrypt_token(access_token) if access_token else ""

    with _db() as conn:
        existing = conn.execute(
            "SELECT github_id, login, name, avatar_url, role, status, token_ciphertext FROM users WHERE github_id=?",
            (github_id,)
        ).fetchone()

        if existing:
            # Preserve existing assigned role and status unless upgraded via env bootstrap
            role = existing["role"]
            if role != "admin" and role_for(login) == "admin":
                role = "admin"
            status = existing["status"] if "status" in existing.keys() else "active"
            
            # If access_token was not passed (e.g. session refresh), preserve existing token
            final_token = token_cipher if access_token else existing["token_ciphertext"]

            conn.execute(
                """UPDATE users SET login=?, name=?, avatar_url=?, role=?, token_ciphertext=?, updated_at=?
                WHERE github_id=?""",
                (login, name, avatar_url, role, final_token, now, github_id)
            )
        else:
            # New user registration: default to 'developer' unless in bootstrap allowlists
            role = role_for(login)
            status = "active"
            conn.execute(
                """INSERT INTO users(github_id, login, name, avatar_url, role, status, token_ciphertext, created_at, updated_at)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (github_id, login, name, avatar_url, role, status, token_cipher, now, now)
            )
            conn.execute(
                "INSERT INTO audit_events(github_id,login,action,resource,detail,created_at) VALUES(?,?,?,?,?,?)",
                (github_id, login, "user.register", f"role:{role}", "", now)
            )

    return {
        "id": github_id,
        "login": login,
        "name": name,
        "avatar_url": avatar_url,
        "role": role,
        "status": status,
        "has_token": bool(token_cipher or (existing and existing["token_ciphertext"] if existing else False))
    }

def create_session(user: dict[str, Any], access_token: str) -> tuple[str, str]:
    now = int(time.time())
    sid, csrf = secrets.token_urlsafe(36), secrets.token_urlsafe(32)
    session_hash = hashlib.sha256(sid.encode()).hexdigest()
    csrf_hash = hashlib.sha256(csrf.encode()).hexdigest()
    user_data = create_or_update_user(user, access_token)
    with _db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.execute(
            "INSERT INTO sessions(session_hash, github_id, csrf_hash, expires_at, created_at) VALUES(?, ?, ?, ?, ?)",
            (session_hash, user_data["id"], csrf_hash, now + SESSION_TTL, now)
        )
    return sid, csrf

def get_session(sid: str) -> dict[str, Any] | None:
    if not sid:
        return None
    session_hash = hashlib.sha256(sid.encode()).hexdigest()
    now = int(time.time())
    with _db() as conn:
        row = conn.execute("""
            SELECT u.github_id, u.login, u.name, u.avatar_url, u.role, u.status, u.token_ciphertext, s.csrf_hash, s.expires_at
            FROM sessions s JOIN users u ON u.github_id=s.github_id
            WHERE s.session_hash=?
        """, (session_hash,)).fetchone()
    if not row:
        return None
    if row["expires_at"] <= now:
        delete_session(sid)
        return None
    
    role = row["role"] or role_for(row["login"])
    status = row["status"] if "status" in row.keys() else "active"
    return {
        "id": row["github_id"],
        "login": row["login"],
        "name": row["name"] if "name" in row.keys() else row["login"],
        "avatar_url": row["avatar_url"],
        "role": role,
        "status": status,
        "access_token": decrypt_token(row["token_ciphertext"]),
        "has_token": bool(row["token_ciphertext"]),
        "csrf_hash": row["csrf_hash"],
        "expires_at": row["expires_at"]
    }

def delete_session(sid: str) -> None:
    if sid:
        session_hash = hashlib.sha256(sid.encode()).hexdigest()
        with _db() as conn:
            conn.execute("DELETE FROM sessions WHERE session_hash=?", (session_hash,))

def disconnect_user(github_id: int) -> None:
    """Disconnect user account: clears stored OAuth tokens and terminates all active sessions."""
    with _db() as conn:
        conn.execute("UPDATE users SET token_ciphertext='', updated_at=? WHERE github_id=?", (int(time.time()), github_id))
        conn.execute("DELETE FROM sessions WHERE github_id=?", (github_id,))

def list_users() -> list[dict[str, Any]]:
    """Retrieve all registered users for Admin User Management."""
    with _db() as conn:
        rows = conn.execute("""
            SELECT github_id, login, name, avatar_url, role, status, token_ciphertext, created_at, updated_at
            FROM users ORDER BY created_at ASC
        """).fetchall()
    users = []
    for r in rows:
        users.append({
            "id": r["github_id"],
            "login": r["login"],
            "name": r["name"] if "name" in r.keys() else r["login"],
            "avatar_url": r["avatar_url"],
            "role": r["role"],
            "status": r["status"] if "status" in r.keys() else "active",
            "has_token": bool(r["token_ciphertext"]),
            "created_at": r["created_at"],
            "updated_at": r["updated_at"]
        })
    return users

def get_user(github_id: int) -> dict[str, Any] | None:
    with _db() as conn:
        r = conn.execute("""
            SELECT github_id, login, name, avatar_url, role, status, token_ciphertext, created_at, updated_at
            FROM users WHERE github_id=?
        """, (github_id,)).fetchone()
    if not r:
        return None
    return {
        "id": r["github_id"],
        "login": r["login"],
        "name": r["name"] if "name" in r.keys() else r["login"],
        "avatar_url": r["avatar_url"],
        "role": r["role"],
        "status": r["status"] if "status" in r.keys() else "active",
        "has_token": bool(r["token_ciphertext"]),
        "created_at": r["created_at"],
        "updated_at": r["updated_at"]
    }

def update_user_role(github_id: int, new_role: str, admin_user: dict[str, Any] | None = None) -> dict[str, Any]:
    allowed_roles = {"admin", "reviewer", "developer"}
    new_role = new_role.lower().strip()
    if new_role not in allowed_roles:
        raise ValueError(f"Invalid role '{new_role}'. Allowed roles: {', '.join(sorted(allowed_roles))}")
    with _db() as conn:
        user = conn.execute("SELECT github_id, login, role FROM users WHERE github_id=?", (github_id,)).fetchone()
        if not user:
            raise KeyError("User not found.")
        old_role = user["role"]
        conn.execute("UPDATE users SET role=?, updated_at=? WHERE github_id=?", (new_role, int(time.time()), github_id))
    audit(admin_user, "rbac.role_change", user["login"], f"Role changed: {old_role} -> {new_role}")
    return {"id": github_id, "login": user["login"], "old_role": old_role, "new_role": new_role}

def update_user_status(github_id: int, new_status: str, admin_user: dict[str, Any] | None = None) -> dict[str, Any]:
    allowed_statuses = {"active", "suspended"}
    new_status = new_status.lower().strip()
    if new_status not in allowed_statuses:
        raise ValueError(f"Invalid status '{new_status}'. Allowed statuses: {', '.join(sorted(allowed_statuses))}")
    with _db() as conn:
        user = conn.execute("SELECT github_id, login, status FROM users WHERE github_id=?", (github_id,)).fetchone()
        if not user:
            raise KeyError("User not found.")
        old_status = user["status"] if "status" in user.keys() else "active"
        conn.execute("UPDATE users SET status=?, updated_at=? WHERE github_id=?", (new_status, int(time.time()), github_id))
        if new_status == "suspended":
            conn.execute("DELETE FROM sessions WHERE github_id=?", (github_id,))
    audit(admin_user, "rbac.status_change", user["login"], f"Status changed: {old_status} -> {new_status}")
    return {"id": github_id, "login": user["login"], "old_status": old_status, "new_status": new_status}

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


def save_security_scan(repo_id: str, user_id: int | None, report: dict[str, Any]) -> dict[str, Any]:
    created_at = int(report.get("scanned_at") or time.time())
    current = report.get("findings", [])
    def key(item: dict[str, Any]) -> str:
        return item.get("fingerprint") or hashlib.sha256(
            f"{item.get('path','')}|{item.get('title','')}|{item.get('category','')}".encode()
        ).hexdigest()
    current_map = {key(item): item for item in current}
    with _db() as conn:
        previous = conn.execute(
            "SELECT findings_json,created_at FROM security_scans WHERE repo_id=? ORDER BY id DESC LIMIT 1",
            (repo_id,)
        ).fetchone()
        previous_items = json.loads(previous["findings_json"]) if previous else []
        previous_map = {key(item): item for item in previous_items}
        new_items = [current_map[fingerprint] for fingerprint in current_map.keys() - previous_map.keys()]
        resolved_items = [previous_map[fingerprint] for fingerprint in previous_map.keys() - current_map.keys()]
        delta = {
            "new_count": len(new_items),
            "resolved_count": len(resolved_items),
            "unchanged_count": len(current_map.keys() & previous_map.keys()),
            "new": [{"path": x.get("path"), "title": x.get("title"), "severity": x.get("severity")} for x in new_items[:50]],
            "resolved": [{"path": x.get("path"), "title": x.get("title"), "severity": x.get("severity")} for x in resolved_items[:50]],
            "previous_scan_at": previous["created_at"] if previous else None,
        }
        conn.execute(
            "INSERT INTO security_scans(repo_id,user_id,created_at,summary_json,findings_json,delta_json) VALUES(?,?,?,?,?,?)",
            (repo_id, user_id, created_at, json.dumps(report.get("summary", {})), json.dumps(current), json.dumps(delta))
        )
    return delta


def load_security_scans(repo_id: str, limit: int = 20) -> list[dict[str, Any]]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT created_at,summary_json,delta_json FROM security_scans WHERE repo_id=? ORDER BY id DESC LIMIT ?",
            (repo_id, min(max(limit, 1), 100))
        ).fetchall()
    return [
        {"created_at": row["created_at"], "summary": json.loads(row["summary_json"]), "delta": json.loads(row["delta_json"])}
        for row in rows
    ]


def save_sentinel_investigation(record: dict[str, Any], user_id: int | None = None) -> None:
    """Persist a complete Sentinel investigation record to SQLite."""
    with _db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO sentinel_investigations (
                id, repo_id, user_id, question, original_transcript, language_code,
                interpreted_query, findings_json, attack_paths_json, graph_entities_json,
                evidence_json, report_markdown, remediation_json, audio_base64, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record["id"],
                record["repo_id"],
                user_id,
                record.get("question", ""),
                record.get("original_transcript", ""),
                record.get("language_code", "en-IN"),
                record.get("interpreted_query", ""),
                json.dumps(record.get("findings", [])),
                json.dumps(record.get("attack_paths", [])),
                json.dumps(record.get("graph_entities", {})),
                json.dumps(record.get("evidence", [])),
                record.get("report_markdown", ""),
                json.dumps(record.get("remediation", [])),
                record.get("audio_base64", ""),
                record.get("created_at", int(time.time()))
            )
        )


def load_sentinel_investigations(repo_id: str | None = None, limit: int = 50, user_id: int | None = None) -> list[dict[str, Any]]:
    """Retrieve saved Sentinel investigations with optional repository filtering."""
    with _db() as conn:
        if repo_id and user_id is not None:
            rows = conn.execute(
                """SELECT * FROM sentinel_investigations
                WHERE repo_id=? AND (user_id=? OR user_id IS NULL)
                ORDER BY created_at DESC LIMIT ?""",
                (repo_id, user_id, min(max(limit, 1), 200))
            ).fetchall()
        elif repo_id:
            rows = conn.execute(
                """SELECT * FROM sentinel_investigations
                WHERE repo_id=?
                ORDER BY created_at DESC LIMIT ?""",
                (repo_id, min(max(limit, 1), 200))
            ).fetchall()
        elif user_id is not None:
            rows = conn.execute(
                """SELECT * FROM sentinel_investigations
                WHERE user_id=? OR user_id IS NULL
                ORDER BY created_at DESC LIMIT ?""",
                (user_id, min(max(limit, 1), 200))
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT * FROM sentinel_investigations
                ORDER BY created_at DESC LIMIT ?""",
                (min(max(limit, 1), 200),)
            ).fetchall()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "repo_id": r["repo_id"],
            "user_id": r["user_id"],
            "question": r["question"],
            "original_transcript": r["original_transcript"],
            "language_code": r["language_code"],
            "interpreted_query": r["interpreted_query"],
            "findings": json.loads(r["findings_json"]) if r["findings_json"] else [],
            "attack_paths": json.loads(r["attack_paths_json"]) if r["attack_paths_json"] else [],
            "graph_entities": json.loads(r["graph_entities_json"]) if r["graph_entities_json"] else {},
            "evidence": json.loads(r["evidence_json"]) if r["evidence_json"] else [],
            "report_markdown": r["report_markdown"],
            "remediation": json.loads(r["remediation_json"]) if r["remediation_json"] else [],
            "has_audio": bool(r["audio_base64"]),
            "created_at": r["created_at"],
        })
    return results


def get_sentinel_investigation(investigation_id: str) -> dict[str, Any] | None:
    """Retrieve full details of a specific Sentinel investigation by ID."""
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM sentinel_investigations WHERE id=?", (investigation_id,)
        ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "repo_id": row["repo_id"],
        "user_id": row["user_id"],
        "question": row["question"],
        "original_transcript": row["original_transcript"],
        "language_code": row["language_code"],
        "interpreted_query": row["interpreted_query"],
        "findings": json.loads(row["findings_json"]) if row["findings_json"] else [],
        "attack_paths": json.loads(row["attack_paths_json"]) if row["attack_paths_json"] else [],
        "graph_entities": json.loads(row["graph_entities_json"]) if row["graph_entities_json"] else {},
        "evidence": json.loads(row["evidence_json"]) if row["evidence_json"] else [],
        "report_markdown": row["report_markdown"],
        "remediation": json.loads(row["remediation_json"]) if row["remediation_json"] else [],
        "audio_base64": row["audio_base64"],
        "created_at": row["created_at"],
    }


def update_sentinel_finding_status(repo_id: str, finding_id: str, status: str, notes: str = "") -> dict[str, Any]:
    """Update finding remediation status (open, under_review, fixed, verified)."""
    valid_statuses = {"open", "under_review", "fixed", "verified"}
    norm_status = status.lower().strip()
    if norm_status not in valid_statuses:
        norm_status = "open"
    now = int(time.time())
    with _db() as conn:
        conn.execute(
            """INSERT INTO sentinel_finding_statuses(finding_id, repo_id, status, notes, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
            status=excluded.status, notes=excluded.notes, updated_at=excluded.updated_at""",
            (finding_id, repo_id, norm_status, notes[:500], now)
        )
    return {"finding_id": finding_id, "repo_id": repo_id, "status": norm_status, "updated_at": now}


def get_sentinel_finding_statuses(repo_id: str) -> dict[str, str]:
    """Retrieve a dictionary mapping finding_id -> status for a repository."""
    with _db() as conn:
        rows = conn.execute(
            "SELECT finding_id, status FROM sentinel_finding_statuses WHERE repo_id=?", (repo_id,)
        ).fetchall()
    return {row["finding_id"]: row["status"] for row in rows}


def delete_sentinel_investigation(investigation_id: str, user_id: int | None = None) -> bool:
    """Delete a stored Sentinel investigation."""
    with _db() as conn:
        if user_id is not None:
            cur = conn.execute(
                "DELETE FROM sentinel_investigations WHERE id=? AND (user_id=? OR user_id IS NULL)",
                (investigation_id, user_id)
            )
        else:
            cur = conn.execute(
                "DELETE FROM sentinel_investigations WHERE id=?", (investigation_id,)
            )
        return cur.rowcount > 0

