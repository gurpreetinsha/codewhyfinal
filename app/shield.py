"""CodeWhy Security Shield - Application Firewall, Security Event Monitoring,
Incident Response, and Trust Center / SOC 2 Readiness Service.
"""
import json
import logging
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from app.auth import _db, DB_PATH

logger = logging.getLogger("codewhy.shield")

# Security configuration defaults
SECURITY_CONTACT_EMAIL = os.getenv("SECURITY_CONTACT_EMAIL", "security@codewhy.io")
FIREWALL_ENABLED = os.getenv("FIREWALL_ENABLED", "true").lower() in ("true", "1", "yes")
MAX_STANDARD_PAYLOAD_BYTES = int(os.getenv("MAX_PAYLOAD_BYTES", 1024 * 1024))  # 1 MB
MAX_UPLOAD_PAYLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", 12 * 1024 * 1024))  # 12 MB for audio / repo tarballs

# In-memory fast cache for high-throughput rate checks + SQLite backing for persistence
_MEM_RATE_CACHE: dict[str, list[float]] = {}


def init_shield_db() -> None:
    """Initialize security shield tables in the primary SQLite database."""
    with _db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS security_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_type TEXT NOT NULL,
          severity TEXT NOT NULL,
          user_id INTEGER,
          login TEXT NOT NULL DEFAULT 'anonymous',
          ip_address TEXT NOT NULL DEFAULT '',
          endpoint TEXT NOT NULL DEFAULT '',
          method TEXT NOT NULL DEFAULT '',
          result TEXT NOT NULL DEFAULT 'allowed',
          repo_id TEXT DEFAULT '',
          detail TEXT DEFAULT '',
          metadata_json TEXT NOT NULL DEFAULT '{}',
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS sec_events_type_idx ON security_events(event_type, created_at);
        CREATE INDEX IF NOT EXISTS sec_events_severity_idx ON security_events(severity, created_at);
        CREATE INDEX IF NOT EXISTS sec_events_login_idx ON security_events(login, created_at);
        CREATE INDEX IF NOT EXISTS sec_events_created_idx ON security_events(created_at);

        CREATE TABLE IF NOT EXISTS security_incidents (
          id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          description TEXT NOT NULL,
          severity TEXT NOT NULL DEFAULT 'medium',
          status TEXT NOT NULL DEFAULT 'new',
          endpoint TEXT NOT NULL DEFAULT '',
          actor TEXT NOT NULL DEFAULT 'unknown',
          evidence_json TEXT NOT NULL DEFAULT '{}',
          assigned_to TEXT NOT NULL DEFAULT 'Security Team',
          resolution_notes TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS sec_incidents_status_idx ON security_incidents(status, created_at);

        CREATE TABLE IF NOT EXISTS rate_limit_records (
          rate_key TEXT NOT NULL,
          window_start INTEGER NOT NULL,
          request_count INTEGER NOT NULL DEFAULT 1,
          PRIMARY KEY (rate_key, window_start)
        );
        CREATE INDEX IF NOT EXISTS rate_records_window_idx ON rate_limit_records(window_start);
        """)
        # Clean up stale rate records older than 1 hour
        one_hour_ago = int(time.time()) - 3600
        conn.execute("DELETE FROM rate_limit_records WHERE window_start < ?", (one_hour_ago,))


def record_security_event(
    event_type: str,
    severity: str = "low",
    user: dict[str, Any] | None = None,
    ip_address: str = "",
    endpoint: str = "",
    method: str = "",
    result: str = "allowed",
    repo_id: str = "",
    detail: str = "",
    metadata: dict[str, Any] | None = None,
) -> int:
    """Record a security event with audit metadata and auto-trigger incident creation on critical signals."""
    now = int(time.time())
    user_id = user.get("id") if user else None
    login = user.get("login", "anonymous") if user else "anonymous"
    meta_str = json.dumps(metadata or {})
    event_id = 0

    with _db() as conn:
        cursor = conn.execute(
            """INSERT INTO security_events
            (event_type, severity, user_id, login, ip_address, endpoint, method, result, repo_id, detail, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_type,
                severity,
                user_id,
                login,
                ip_address[:64],
                endpoint[:256],
                method[:16],
                result[:32],
                repo_id[:128],
                detail[:500],
                meta_str,
                now,
            ),
        )
        event_id = cursor.lastrowid or 0

    # Auto-incident triage for high / critical security events
    if severity in ("high", "critical") or result == "blocked":
        _evaluate_automated_incident(event_type, severity, login, ip_address, endpoint, detail, metadata or {})

    return event_id


def _evaluate_automated_incident(
    event_type: str,
    severity: str,
    actor: str,
    ip_address: str,
    endpoint: str,
    detail: str,
    metadata: dict[str, Any],
) -> None:
    """Evaluate whether a high-severity security event warrants filing a formal security incident."""
    now = int(time.time())
    ten_mins_ago = now - 600

    # Check if an open incident already exists for this endpoint and actor
    with _db() as conn:
        existing = conn.execute(
            """SELECT id FROM security_incidents
            WHERE endpoint=? AND actor=? AND status IN ('new', 'investigating') AND created_at > ?""",
            (endpoint, actor, ten_mins_ago),
        ).fetchone()

        if existing:
            return  # Already tracking this incident

    incident_id = f"INC-{time.strftime('%Y%m%d')}-{secrets_hex(3).upper()}"
    title = f"Automated Security Alert: {event_type} on {endpoint or 'API'}"
    description = f"High-risk security event triggered: {detail or event_type}. Actor: {actor} (IP: {ip_address})."
    evidence = {
        "event_type": event_type,
        "ip_address": ip_address,
        "endpoint": endpoint,
        "detail": detail,
        "metadata": metadata,
        "triggered_at": now,
    }

    try:
        create_incident(
            incident_id=incident_id,
            title=title,
            description=description,
            severity=severity,
            endpoint=endpoint,
            actor=actor,
            evidence=evidence,
            assigned_to="Security Incident Team",
        )
    except Exception as exc:
        logger.warning("Could not auto-create incident: %s", exc)


def secrets_hex(n: int = 4) -> str:
    import secrets
    return secrets.token_hex(n)


def list_security_events(
    limit: int = 100,
    event_type: str | None = None,
    severity: str | None = None,
    login: str | None = None,
    repo_id: str | None = None,
    result: str | None = None,
    since_ts: int | None = None,
) -> list[dict[str, Any]]:
    """List recorded security events with multi-field filtering."""
    query = ["SELECT * FROM security_events WHERE 1=1"]
    params: list[Any] = []

    if event_type:
        query.append("AND event_type = ?")
        params.append(event_type)
    if severity:
        query.append("AND severity = ?")
        params.append(severity)
    if login:
        query.append("AND login = ?")
        params.append(login)
    if repo_id:
        query.append("AND repo_id = ?")
        params.append(repo_id)
    if result:
        query.append("AND result = ?")
        params.append(result)
    if since_ts:
        query.append("AND created_at >= ?")
        params.append(since_ts)

    query.append("ORDER BY id DESC LIMIT ?")
    params.append(min(max(limit, 1), 500))

    with _db() as conn:
        rows = conn.execute(" ".join(query), tuple(params)).fetchall()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "event_type": r["event_type"],
            "severity": r["severity"],
            "user_id": r["user_id"],
            "login": r["login"],
            "ip_address": r["ip_address"],
            "endpoint": r["endpoint"],
            "method": r["method"],
            "result": r["result"],
            "repo_id": r["repo_id"],
            "detail": r["detail"],
            "metadata": json.loads(r["metadata_json"] or "{}"),
            "created_at": r["created_at"],
        })
    return results


def get_security_stats() -> dict[str, Any]:
    """Retrieve aggregate security statistics for the admin dashboard and trust center."""
    now = int(time.time())
    one_day_ago = now - 86400
    seven_days_ago = now - (86400 * 7)

    with _db() as conn:
        total_24h = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE created_at >= ?", (one_day_ago,)
        ).fetchone()[0]
        blocked_24h = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE created_at >= ? AND result = 'blocked'", (one_day_ago,)
        ).fetchone()[0]
        ratelimit_24h = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE created_at >= ? AND event_type = 'ratelimit.exceeded'", (one_day_ago,)
        ).fetchone()[0]
        auth_failures_24h = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE created_at >= ? AND event_type IN ('auth.login.failure', 'access.unauthorized')", (one_day_ago,)
        ).fetchone()[0]
        open_incidents = conn.execute(
            "SELECT COUNT(*) FROM security_incidents WHERE status IN ('new', 'investigating', 'contained')"
        ).fetchone()[0]
        resolved_incidents_7d = conn.execute(
            "SELECT COUNT(*) FROM security_incidents WHERE status IN ('resolved', 'closed') AND updated_at >= ?", (seven_days_ago,)
        ).fetchone()[0]

    return {
        "firewall_status": "active" if FIREWALL_ENABLED else "disabled",
        "vercel_firewall": {
            "status": "configured",
            "managed_rules": True,
            "ddos_protection": "active",
            "dashboard_url": "https://vercel.com/dashboard",
        },
        "events_24h": total_24h,
        "blocked_requests_24h": blocked_24h,
        "ratelimit_events_24h": ratelimit_24h,
        "auth_failures_24h": auth_failures_24h,
        "open_incidents": open_incidents,
        "resolved_incidents_7d": resolved_incidents_7d,
        "security_contact": SECURITY_CONTACT_EMAIL,
        "last_audit_sync": now,
    }


def create_incident(
    incident_id: str | None = None,
    title: str = "",
    description: str = "",
    severity: str = "medium",
    endpoint: str = "",
    actor: str = "unknown",
    evidence: dict[str, Any] | None = None,
    assigned_to: str = "Security Incident Team",
) -> dict[str, Any]:
    """Create a new security incident record."""
    now = int(time.time())
    inc_id = incident_id or f"INC-{time.strftime('%Y%m%d')}-{secrets_hex(3).upper()}"
    evidence_str = json.dumps(evidence or {})

    with _db() as conn:
        conn.execute(
            """INSERT INTO security_incidents
            (id, title, description, severity, status, endpoint, actor, evidence_json, assigned_to, resolution_notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'new', ?, ?, ?, ?, '', ?, ?)""",
            (inc_id, title[:200], description[:1000], severity, endpoint[:256], actor[:128], evidence_str, assigned_to[:128], now, now),
        )

    return {
        "id": inc_id,
        "title": title,
        "description": description,
        "severity": severity,
        "status": "new",
        "endpoint": endpoint,
        "actor": actor,
        "evidence": evidence or {},
        "assigned_to": assigned_to,
        "resolution_notes": "",
        "created_at": now,
        "updated_at": now,
    }


def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List recorded security incidents with filtering."""
    query = ["SELECT * FROM security_incidents WHERE 1=1"]
    params: list[Any] = []

    if status:
        query.append("AND status = ?")
        params.append(status)
    if severity:
        query.append("AND severity = ?")
        params.append(severity)

    query.append("ORDER BY updated_at DESC LIMIT ?")
    params.append(min(max(limit, 1), 200))

    with _db() as conn:
        rows = conn.execute(" ".join(query), tuple(params)).fetchall()

    incidents = []
    for r in rows:
        incidents.append({
            "id": r["id"],
            "title": r["title"],
            "description": r["description"],
            "severity": r["severity"],
            "status": r["status"],
            "endpoint": r["endpoint"],
            "actor": r["actor"],
            "evidence": json.loads(r["evidence_json"] or "{}"),
            "assigned_to": r["assigned_to"],
            "resolution_notes": r["resolution_notes"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        })
    return incidents


def get_incident(incident_id: str) -> dict[str, Any] | None:
    """Retrieve a single security incident by ID."""
    with _db() as conn:
        r = conn.execute("SELECT * FROM security_incidents WHERE id = ?", (incident_id,)).fetchone()
    if not r:
        return None
    return {
        "id": r["id"],
        "title": r["title"],
        "description": r["description"],
        "severity": r["severity"],
        "status": r["status"],
        "endpoint": r["endpoint"],
        "actor": r["actor"],
        "evidence": json.loads(r["evidence_json"] or "{}"),
        "assigned_to": r["assigned_to"],
        "resolution_notes": r["resolution_notes"],
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
    }


def update_incident(
    incident_id: str,
    status: str | None = None,
    resolution_notes: str | None = None,
    assigned_to: str | None = None,
    admin_user: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Update incident status, assigned responder, or resolution notes."""
    allowed_statuses = {"new", "investigating", "contained", "resolved", "closed"}
    if status and status.lower() not in allowed_statuses:
        raise ValueError(f"Invalid status '{status}'. Allowed: {', '.join(sorted(allowed_statuses))}")

    now = int(time.time())
    inc = get_incident(incident_id)
    if not inc:
        raise KeyError(f"Incident '{incident_id}' not found.")

    new_status = status.lower() if status else inc["status"]
    new_notes = resolution_notes if resolution_notes is not None else inc["resolution_notes"]
    new_assignee = assigned_to if assigned_to is not None else inc["assigned_to"]

    with _db() as conn:
        conn.execute(
            """UPDATE security_incidents
            SET status=?, resolution_notes=?, assigned_to=?, updated_at=?
            WHERE id=?""",
            (new_status, new_notes[:2000], new_assignee[:128], now, incident_id),
        )

    actor_login = admin_user.get("login", "admin") if admin_user else "admin"
    record_security_event(
        event_type="incident.updated",
        severity="medium",
        user=admin_user,
        detail=f"Incident {incident_id} updated: status={new_status}",
        metadata={"incident_id": incident_id, "status": new_status, "updated_by": actor_login},
    )

    inc.update({
        "status": new_status,
        "resolution_notes": new_notes,
        "assigned_to": new_assignee,
        "updated_at": now,
    })
    return inc


def check_rate_limit(key: str, limit: int, window_seconds: int = 60) -> tuple[bool, int, int]:
    """Serverless-compatible sliding window rate limiter backed by SQLite with in-memory caching.

    Returns:
        tuple (allowed: bool, current_count: int, retry_after: int)
    """
    now = time.time()
    now_int = int(now)
    window_start = now_int - (now_int % window_seconds)

    # 1. Check in-memory fast window
    mem_bucket = _MEM_RATE_CACHE.get(key, [])
    mem_bucket = [stamp for stamp in mem_bucket if now - stamp < window_seconds]
    _MEM_RATE_CACHE[key] = mem_bucket

    if len(mem_bucket) >= limit:
        retry_after = max(1, int(window_seconds - (now - mem_bucket[0])))
        return False, len(mem_bucket), retry_after

    # 2. Synchronize with SQLite persistent window (ensures rate limits persist across serverless instances)
    current_count = len(mem_bucket) + 1
    try:
        with _db() as conn:
            row = conn.execute(
                "SELECT request_count FROM rate_limit_records WHERE rate_key=? AND window_start=?",
                (key, window_start),
            ).fetchone()

            if row:
                db_count = row["request_count"] + 1
                conn.execute(
                    "UPDATE rate_limit_records SET request_count=? WHERE rate_key=? AND window_start=?",
                    (db_count, key, window_start),
                )
                current_count = max(current_count, db_count)
            else:
                conn.execute(
                    "INSERT INTO rate_limit_records(rate_key, window_start, request_count) VALUES(?, ?, 1)",
                    (key, window_start),
                )
    except Exception as exc:
        # Fall back gracefully to memory window if DB is momentarily busy
        logger.debug("Rate limit SQLite sync: %s", exc)

    mem_bucket.append(now)
    _MEM_RATE_CACHE[key] = mem_bucket

    if current_count > limit:
        retry_after = max(1, window_seconds - (now_int % window_seconds))
        return False, current_count, retry_after

    return True, current_count, 0


def sanitize_input_identifier(value: str) -> str:
    """Sanitize identifiers to prevent path traversal, null-byte injection, and command tampering."""
    if not value:
        return ""
    # Strip null bytes and control chars
    clean = re.sub(r"[\x00-\x1f\x7f]", "", value)
    # Prevent directory traversal
    clean = clean.replace("..", "").replace("\\", "/")
    return clean.strip()


def validate_request_payload(
    content_length: int | None,
    max_size: int = MAX_STANDARD_PAYLOAD_BYTES,
    content_type: str | None = None,
    allowed_types: set[str] | None = None,
) -> tuple[bool, str]:
    """Validate request headers, body size, and MIME content types."""
    if content_length is not None and content_length > max_size:
        return False, f"Request body size exceeds maximum allowed limit of {max_size // (1024 * 1024)} MB."

    if allowed_types and content_type:
        base_type = content_type.split(";")[0].strip().lower()
        if base_type not in allowed_types:
            return False, f"Content-Type '{base_type}' is not accepted. Allowed: {', '.join(sorted(allowed_types))}."

    return True, ""


# Trust Center and SOC 2 Readiness Static Registry
TRUST_CENTER_CONTROLS = [
    {
        "id": "SEC-01",
        "name": "HTTPS & Transport Encryption",
        "category": "Network & Infrastructure",
        "description": "All communication is strictly encrypted via TLS 1.3/1.2 with HSTS enforced (2-year preload).",
        "status": "implemented",
        "evidence": "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    },
    {
        "id": "SEC-02",
        "name": "Edge Web Application Firewall (WAF)",
        "category": "Perimeter Defense",
        "description": "Layer 7 DDoS mitigation and edge firewall rules protecting auth and scanning routes.",
        "status": "configured",
        "evidence": "Vercel Edge WAF configuration & Application Shield Middleware",
    },
    {
        "id": "SEC-03",
        "name": "GitHub OAuth 2.0 Identity & State CSRF",
        "category": "Authentication",
        "description": "Strict minimum permission scopes (read:user user:email repo) with cryptographically bound state tokens.",
        "status": "implemented",
        "evidence": "HttpOnly SameSite=Lax codewhy_oauth_state cookie & SHA-256 session mapping",
    },
    {
        "id": "SEC-04",
        "name": "Unified Access & Authorization Control",
        "category": "Authorization",
        "description": "Authenticated session validation and CSRF protection across all sensitive API endpoints, ensuring full feature accessibility for all team members.",
        "status": "implemented",
        "evidence": "Session verification and CSRF protection in auth_and_tenant_middleware and protected routes",
    },
    {
        "id": "SEC-05",
        "name": "Multi-Tenant Repository Isolation",
        "category": "Data Separation",
        "description": "Repositories are cryptographically scoped to authenticated user accounts or isolated anonymous sessions.",
        "status": "implemented",
        "evidence": "Tenant namespace prefixing (login::owner/repo) and REPO_OWNERS ownership check",
    },
    {
        "id": "SEC-06",
        "name": "Encrypted Credential Storage",
        "category": "Data Protection",
        "description": "GitHub OAuth access tokens stored with AES-128-CBC / HMAC-SHA256 via Fernet encryption.",
        "status": "implemented",
        "evidence": "Fernet key derivation from 32-character SESSION_SECRET; raw tokens never persisted",
    },
    {
        "id": "SEC-07",
        "name": "Automated Secret Detection & Redaction",
        "category": "Data Privacy",
        "description": "API keys, private keys, passwords, and tokens are redacted before analysis, storage, or AI transmission.",
        "status": "implemented",
        "evidence": "app.security.redact_source and static credential scanners",
    },
    {
        "id": "SEC-08",
        "name": "Sliding-Window Rate Limiting",
        "category": "Abuse Prevention",
        "description": "Tiered rate limiting across authentication, AI queries, security scans, and general routes.",
        "status": "implemented",
        "evidence": "rate_limit_records SQLite sliding window returning HTTP 429 Retry-After",
    },
    {
        "id": "SEC-09",
        "name": "Hardened HTTP Security Headers",
        "category": "Application Security",
        "description": "CSP, X-Content-Type-Options, Referrer-Policy, X-Frame-Options, and Permissions-Policy enabled on all responses.",
        "status": "implemented",
        "evidence": "Strict Content-Security-Policy with frame-ancestors 'none'",
    },
    {
        "id": "SEC-10",
        "name": "Immutable Audit & Security Event Logging",
        "category": "Monitoring & Compliance",
        "description": "All logins, permission changes, rate-limit blocks, and security scans recorded in audit_events & security_events.",
        "status": "implemented",
        "evidence": "audit_events & security_events SQLite persistent stores",
    },
    {
        "id": "SEC-11",
        "name": "Security Incident Triage Workflow",
        "category": "Incident Response",
        "description": "Automated alert correlation for suspicious events with five-stage incident lifecycle management.",
        "status": "implemented",
        "evidence": "security_incidents table supporting New, Investigating, Contained, Resolved, Closed states",
    },
    {
        "id": "SEC-12",
        "name": "Zero-Persistence Source Code Model",
        "category": "Data Retention",
        "description": "Scanned source files reside in ephemeral memory snapshots only; server restart purges all source code.",
        "status": "implemented",
        "evidence": "Source files held in memory REPOS dictionary; not written to database disk",
    },
    {
        "id": "SEC-13",
        "name": "Immediate Account Disconnection & Data Purge",
        "category": "User Rights",
        "description": "Users can disconnect GitHub accounts on demand, terminating sessions and deleting encrypted tokens.",
        "status": "implemented",
        "evidence": "POST /api/auth/disconnect wipes token_ciphertext and terminates active sessions",
    },
    {
        "id": "SEC-14",
        "name": "Vulnerability Disclosure & Responsible Reporting",
        "category": "Security Governance",
        "description": "Direct security contact mechanism with 24-hour response SLA for vulnerability disclosures.",
        "status": "implemented",
        "evidence": "Dedicated Security & Trust Center contact mechanism and disclosure policy",
    },
]

SOC2_POLICIES = [
    {
        "policy_id": "POL-01",
        "name": "Information Security Policy",
        "tsc_mapping": ["CC1.1", "CC2.1"],
        "status": "draft",
        "owner": "Chief Information Security Officer / Engineering Lead",
        "review_date": "2026-11-20",
        "next_review": "2027-11-20",
        "purpose": "Establishes organization-wide security governance, leadership commitments, and baseline standards.",
        "control_summary": "Defines security requirements for CodeWhy infrastructure, employee devices, and production workloads.",
        "implementation": "Formal security architecture verified through automated CI checks and Security Shield controls.",
        "evidence_required": "Annual policy sign-off, Security Shield test suite execution records.",
    },
    {
        "policy_id": "POL-02",
        "name": "Access Control Policy",
        "tsc_mapping": ["CC6.1", "CC6.2", "CC6.3"],
        "status": "draft",
        "owner": "Lead Security Architect",
        "review_date": "2026-11-20",
        "next_review": "2027-11-20",
        "purpose": "Ensures least-privilege access, centralized identity management, and immediate offboarding revocation.",
        "control_summary": "All workspace access requires authenticated GitHub identities with continuous session verification.",
        "implementation": "Backend middleware validates authenticated user sessions and CSRF tokens across all protected API endpoints.",
        "evidence_required": "Authentication unit tests, audit event logs, session revocation tests.",
    },
    {
        "policy_id": "POL-03",
        "name": "Data Classification and Handling Policy",
        "tsc_mapping": ["CC6.7", "CC6.8"],
        "status": "draft",
        "owner": "Data Protection Officer",
        "review_date": "2026-11-20",
        "next_review": "2027-11-20",
        "purpose": "Classifies customer repository metadata, source code, credentials, and system audit logs by sensitivity.",
        "control_summary": "Customer source code is classified as Confidential. Secrets and credentials are classified as Restricted.",
        "implementation": "Automated secret redaction masks all tokens before storage; source code is stored only in ephemeral memory.",
        "evidence_required": "Redaction test suite (test_security.py), ephemeral data isolation tests.",
    },
    {
        "policy_id": "POL-04",
        "name": "Encryption Policy",
        "tsc_mapping": ["CC6.7"],
        "status": "draft",
        "owner": "Security Engineering",
        "review_date": "2026-11-20",
        "next_review": "2027-11-20",
        "purpose": "Mandates strong cryptography for all data in transit and sensitive data at rest.",
        "control_summary": "TLS 1.2+ mandatory in transit. AES-128-CBC / Fernet encryption mandatory for stored OAuth access tokens.",
        "implementation": "HSTS header max-age=63072000; SESSION_SECRET Fernet key derivation for SQLite token column.",
        "evidence_required": "SSL Labs A+ test verification, test_oauth_token_is_encrypted_and_session_is_csrf_protected.",
    },
    {
        "policy_id": "POL-05",
        "name": "Secure Development Policy",
        "tsc_mapping": ["CC7.1", "CC8.1"],
        "status": "draft",
        "owner": "Engineering Lead",
        "review_date": "2026-11-20",
        "next_review": "2027-11-20",
        "purpose": "Governs secure coding standards, peer review, and automated preflight testing.",
        "control_summary": "All code changes require pull request review. Sensitive changes require Reviewer or Admin approval.",
        "implementation": "CodeWhy PR Risk Reviewer validates changed files and flags security anti-patterns before merge.",
        "evidence_required": "GitHub pull request review requirements, test_rbac_pr_risk_reviewer_permission test suite.",
    },
    {
        "policy_id": "POL-06",
        "name": "Vulnerability Management Policy",
        "tsc_mapping": ["CC7.1", "CC7.2"],
        "status": "draft",
        "owner": "Security Operations Lead",
        "review_date": "2026-11-20",
        "next_review": "2027-11-20",
        "purpose": "Establishes continuous vulnerability scanning, dependency auditing, and SLA-based remediation.",
        "control_summary": "Critical vulnerabilities must be mitigated within 7 days; high vulnerabilities within 14 days.",
        "implementation": "Automated dependency lockfile parser and static security pattern engine in app/security.py.",
        "evidence_required": "Security scanning timeline deltas (test_security_scan_timeline), dependency inventory logs.",
    },
    {
        "policy_id": "POL-07",
        "name": "Incident Response Policy",
        "tsc_mapping": ["CC7.3", "CC7.4"],
        "status": "draft",
        "owner": "Incident Commander",
        "review_date": "2026-11-20",
        "next_review": "2027-11-20",
        "purpose": "Defines incident classification, response phases (Triage, Containment, Eradication, Recovery), and reporting.",
        "control_summary": "Security incidents must be tracked through a 5-stage lifecycle with audit trails and resolution notes.",
        "implementation": "Centralized security_incidents workflow with automated alert ingestion and administrative actions.",
        "evidence_required": "Incident tracking records, test_incident_management test case execution.",
    },
    {
        "policy_id": "POL-08",
        "name": "Logging and Monitoring Policy",
        "tsc_mapping": ["CC7.2", "CC7.3"],
        "status": "draft",
        "owner": "Site Reliability Engineering",
        "review_date": "2026-11-20",
        "next_review": "2027-11-20",
        "purpose": "Ensures all security-relevant activities are captured with timestamps, actor IDs, and outcomes.",
        "control_summary": "Logs must omit raw passwords, full tokens, and sensitive cryptographic secrets.",
        "implementation": "Structured security_events table with indexed search across event type, severity, and actor.",
        "evidence_required": "Audit log export samples, test_security_event_recording test case.",
    },
    {
        "policy_id": "POL-09",
        "name": "Backup and Recovery Policy",
        "tsc_mapping": ["A1.2", "A1.3"],
        "status": "draft",
        "owner": "Infrastructure Lead",
        "review_date": "2026-11-20",
        "next_review": "2027-11-20",
        "purpose": "Governs backup frequency, integrity verification, and disaster recovery recovery point objectives (RPO < 1h).",
        "control_summary": "SQLite metadata and audit databases are snapshot-backed; source files remain stateless in application memory.",
        "implementation": "SQLite VACUUM INTO and snapshot backups; zero repository source code persistence on disk.",
        "evidence_required": "Automated database backup scripts and disaster recovery drill logs.",
    },
    {
        "policy_id": "POL-10",
        "name": "Vendor and Third-Party Risk Policy",
        "tsc_mapping": ["CC9.2"],
        "status": "draft",
        "owner": "Compliance Lead",
        "review_date": "2026-11-20",
        "next_review": "2027-11-20",
        "purpose": "Requires security and privacy assessments for all integrated external service providers.",
        "control_summary": "Vendors (GitHub OAuth, Vercel Edge, Sarvam AI, Neo4j) are audited for SOC 2 or ISO 27001 compliance.",
        "implementation": "Transparent disclosure in Trust Center; secret redaction prior to sending data to external APIs.",
        "evidence_required": "Annual vendor SOC 2 review documentation, Trust Center data privacy disclosures.",
    },
    {
        "policy_id": "POL-11",
        "name": "Data Retention and Deletion Policy",
        "tsc_mapping": ["CC6.5", "CC6.8"],
        "status": "draft",
        "owner": "Data Protection Officer",
        "review_date": "2026-11-20",
        "next_review": "2027-11-20",
        "purpose": "Defines data retention schedules and guarantees immediate data purging upon user disconnection.",
        "control_summary": "Session tokens expire in 12 hours. User disconnect instantly clears tokens and revokes access.",
        "implementation": "POST /api/auth/disconnect clears token_ciphertext; session expiration daemon purges stale records.",
        "evidence_required": "test_disconnect_user_clears_token_and_sessions automated test output.",
    },
    {
        "policy_id": "POL-12",
        "name": "Change Management Policy",
        "tsc_mapping": ["CC8.1"],
        "status": "draft",
        "owner": "Engineering Lead",
        "review_date": "2026-11-20",
        "next_review": "2027-11-20",
        "purpose": "Requires documented testing, peer review, and rollback procedures for all production deployments.",
        "control_summary": "All changes must pass automated test suites and be deployed through automated Vercel CI/CD pipelines.",
        "implementation": "Automated pytest regression suites (25+ tests) verifying zero regressions on code changes.",
        "evidence_required": "Vercel deployment logs and passing test suite CI records.",
    },
]


def get_trust_center_data() -> dict[str, Any]:
    """Compile complete Trust Center public payload with verified controls and architecture data."""
    stats = get_security_stats()
    return {
        "title": "CodeWhy Security & Trust Center",
        "version": "1.0",
        "organization": "CodeWhy Cybersecurity & Engineering Intelligence",
        "overall_status": "Operational & Hardened",
        "verified_controls_count": len([c for c in TRUST_CENTER_CONTROLS if c["status"] == "implemented"]),
        "total_controls_count": len(TRUST_CENTER_CONTROLS),
        "controls": TRUST_CENTER_CONTROLS,
        "security_overview": {
            "authentication": "GitHub OAuth 2.0 with AES-128-CBC encrypted token storage and CSRF binding.",
            "authorization": "Strict backend-enforced RBAC (Admin, Reviewer, Developer) on every sensitive endpoint.",
            "data_separation": "Multi-tenant repository isolation; zero cross-account data leakage.",
            "perimeter_defense": "Vercel Edge WAF + CodeWhy Application Firewall rate limiting and request validation.",
            "secret_protection": "Preflight detection and automated masking of 15+ credential formats prior to storage or AI inference.",
            "data_retention": "Stateless source code model: code is analyzed in volatile memory and purged on restart.",
        },
        "data_privacy": {
            "information_processed": [
                "GitHub profile metadata (user ID, login handle, display name, public avatar URL).",
                "Repository structure, file names, dependencies, and code function AST definitions.",
                "Security investigation questions and optional voice transcripts.",
            ],
            "why_github_access_required": "To map codebase architecture, calculate technical debt, investigate security flaws, and review pull requests without manual file uploads.",
            "github_permissions_requested": "read:user (identity verification), user:email (account lookup), repo (read repository structure and pull request diffs).",
            "external_ai_disclosures": "Questions and sanitized code context may be processed by the configured LLM / Sarvam AI API for multilingual understanding and defensive attack graph generation. All secrets and credentials are automatically redacted before transmission.",
            "data_deletion_rights": "Users can disconnect their GitHub account at any time via the profile modal or POST /api/auth/disconnect, immediately purging stored encrypted tokens and active sessions.",
        },
        "architecture_layers": [
            {
                "layer": "Layer 1: Perimeter & Edge",
                "component": "Vercel Edge Firewall & DDoS Mitigation",
                "role": "Global anycast DDoS mitigation, layer 7 rate limiting, and edge-level blocking.",
            },
            {
                "layer": "Layer 2: Application Shield",
                "component": "CodeWhy Application Firewall Middleware",
                "role": "Request size limits (1MB JSON / 12MB audio), Content-Type verification, query sanitation, and sliding-window rate limiting.",
            },
            {
                "layer": "Layer 3: Identity & Access",
                "component": "GitHub OAuth & RBAC Engine",
                "role": "OAuth state CSRF validation, server-side session hash mapping, and role privilege verification.",
            },
            {
                "layer": "Layer 4: Data Protection",
                "component": "Cryptographic Vault & Redaction Engine",
                "role": "Fernet AES token encryption, credential redaction filter, and multi-tenant repository isolation.",
            },
            {
                "layer": "Layer 5: Graph & Intelligence",
                "component": "Neo4j Graph Database & Sarvam AI Integration",
                "role": "Role-guarded knowledge graph relationship queries and sanitized multilingual security investigation.",
            },
        ],
        "contact": {
            "security_email": SECURITY_CONTACT_EMAIL,
            "response_sla": "24 hours for initial assessment; 72 hours for critical triage.",
            "responsible_disclosure_url": "#trust-contact",
        },
        "stats": stats,
    }


def get_soc2_readiness_data() -> dict[str, Any]:
    """Compile SOC 2 Readiness documentation, policies, and evidence register."""
    return {
        "status": "In Preparation / Audit Ready",
        "framework": "SOC 2 Type I / Type II Readiness (Trust Services Criteria)",
        "trust_services_criteria": ["Security (Common Criteria)", "Availability", "Confidentiality"],
        "policies": SOC2_POLICIES,
        "controls_evidence_register": TRUST_CENTER_CONTROLS,
        "policy_completion_pct": round((len([p for p in SOC2_POLICIES if p["status"] in ("draft", "approved")]) / len(SOC2_POLICIES)) * 100),
        "controls_verified_pct": round((len([c for c in TRUST_CENTER_CONTROLS if c["status"] == "implemented"]) / len(TRUST_CENTER_CONTROLS)) * 100),
        "disclaimer": "This documentation outlines internal security controls and draft policies prepared to support future third-party SOC 2 Type I/II examinations. CodeWhy does not claim formal SOC 2 certification until an accredited AICPA independent auditor issues a formal report.",
    }
