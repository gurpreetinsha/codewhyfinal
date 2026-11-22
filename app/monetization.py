"""Demo subscriptions and per-user Sarvam API keys.

This module is additive: it does not alter CODEWHY's existing analysis pipeline.
"""
from __future__ import annotations

import os
import sqlite3
import time
from typing import Any

from app.auth import _db, encrypt_token, decrypt_token

PLANS: dict[str, dict[str, Any]] = {
    "free": {"name": "Free", "price": 0, "currency": "INR", "monthly_ai_requests": 50, "repositories": 2, "features": ["Core codebase analysis", "Basic security insights", "Community support"]},
    "pro": {"name": "Pro", "price": 499, "currency": "INR", "monthly_ai_requests": 1000, "repositories": 20, "features": ["Everything in Free", "Advanced investigations", "Higher monthly AI allowance", "Priority support"]},
    "business": {"name": "Business", "price": 1999, "currency": "INR", "monthly_ai_requests": 5000, "repositories": 100, "features": ["Everything in Pro", "Team-ready allowance", "Centralized usage visibility", "Dedicated support"]},
}


def init_monetization_db() -> None:
    with _db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS user_subscriptions (
          github_id INTEGER PRIMARY KEY,
          plan_id TEXT NOT NULL DEFAULT 'free',
          status TEXT NOT NULL DEFAULT 'active',
          billing_mode TEXT NOT NULL DEFAULT 'demo',
          started_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS user_sarvam_keys (
          github_id INTEGER PRIMARY KEY,
          key_ciphertext TEXT NOT NULL,
          key_hint TEXT NOT NULL DEFAULT '',
          updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscription_usage (
          github_id INTEGER NOT NULL,
          period TEXT NOT NULL,
          ai_requests INTEGER NOT NULL DEFAULT 0,
          updated_at INTEGER NOT NULL,
          PRIMARY KEY(github_id, period)
        );
        """)


def get_subscription(github_id: int) -> dict[str, Any]:
    now = int(time.time())
    period = time.strftime("%Y-%m", time.gmtime(now))
    with _db() as conn:
        row = conn.execute("SELECT plan_id,status,billing_mode,started_at,updated_at FROM user_subscriptions WHERE github_id=?", (github_id,)).fetchone()
        if not row:
            conn.execute("INSERT OR IGNORE INTO user_subscriptions(github_id,plan_id,status,billing_mode,started_at,updated_at) VALUES(?,?,?,?,?,?)", (github_id, "free", "active", "demo", now, now))
            plan_id, status, billing_mode, started_at, updated_at = "free", "active", "demo", now, now
        else:
            plan_id, status, billing_mode, started_at, updated_at = row["plan_id"], row["status"], row["billing_mode"], row["started_at"], row["updated_at"]
        usage = conn.execute("SELECT ai_requests FROM subscription_usage WHERE github_id=? AND period=?", (github_id, period)).fetchone()
        used = int(usage["ai_requests"]) if usage else 0
    if plan_id not in PLANS:
        plan_id = "free"
    plan = PLANS[plan_id]
    return {"plan_id": plan_id, "plan": plan, "status": status, "billing_mode": billing_mode, "started_at": started_at, "updated_at": updated_at, "usage": {"period": period, "ai_requests": used, "monthly_limit": plan["monthly_ai_requests"], "remaining": max(0, plan["monthly_ai_requests"] - used)}}


def set_demo_plan(github_id: int, plan_id: str) -> dict[str, Any]:
    if plan_id not in PLANS:
        raise ValueError("Choose a valid subscription plan.")
    now = int(time.time())
    with _db() as conn:
        conn.execute("""INSERT INTO user_subscriptions(github_id,plan_id,status,billing_mode,started_at,updated_at)
          VALUES(?,?, 'active','demo',?,?)
          ON CONFLICT(github_id) DO UPDATE SET plan_id=excluded.plan_id,status='active',billing_mode='demo',updated_at=excluded.updated_at""", (github_id, plan_id, now, now))
    return get_subscription(github_id)


def record_ai_usage(github_id: int) -> None:
    now = int(time.time())
    period = time.strftime("%Y-%m", time.gmtime(now))
    with _db() as conn:
        conn.execute("""INSERT INTO subscription_usage(github_id,period,ai_requests,updated_at)
          VALUES(?,?,1,?) ON CONFLICT(github_id,period)
          DO UPDATE SET ai_requests=ai_requests+1,updated_at=excluded.updated_at""", (github_id, period, now))


def save_sarvam_key(github_id: int, api_key: str) -> None:
    encrypted = encrypt_token(api_key)
    now = int(time.time())
    hint = api_key[-4:]
    with _db() as conn:
        conn.execute("""INSERT INTO user_sarvam_keys(github_id,key_ciphertext,key_hint,updated_at)
          VALUES(?,?,?,?) ON CONFLICT(github_id)
          DO UPDATE SET key_ciphertext=excluded.key_ciphertext,key_hint=excluded.key_hint,updated_at=excluded.updated_at""", (github_id, encrypted, hint, now))


def get_sarvam_key(github_id: int | None) -> str:
    if not github_id:
        return ""
    try:
        with _db() as conn:
            row = conn.execute("SELECT key_ciphertext FROM user_sarvam_keys WHERE github_id=?", (github_id,)).fetchone()
    except sqlite3.OperationalError as exc:
        # Some existing tests/tools recreate the auth database after app import.
        # Treat an absent optional BYOK table as "no personal key", not an app outage.
        if "no such table" in str(exc).lower():
            return ""
        raise
    return decrypt_token(row["key_ciphertext"]) if row else ""


def sarvam_key_status(github_id: int) -> dict[str, Any]:
    with _db() as conn:
        row = conn.execute("SELECT key_hint,updated_at FROM user_sarvam_keys WHERE github_id=?", (github_id,)).fetchone()
    return {"configured": bool(row), "masked_key": ("••••••••" + row["key_hint"]) if row else "", "updated_at": row["updated_at"] if row else None}


def delete_sarvam_key(github_id: int) -> None:
    with _db() as conn:
        conn.execute("DELETE FROM user_sarvam_keys WHERE github_id=?", (github_id,))
