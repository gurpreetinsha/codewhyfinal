from __future__ import annotations

from app import auth
from app import monetization


def setup_isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "DB_PATH", str(tmp_path / "monetization.sqlite3"))
    monkeypatch.setattr(auth, "SESSION_SECRET", "test-session-secret-with-more-than-32-characters")
    monetization.init_monetization_db()


def test_demo_subscription_defaults_and_plan_changes(tmp_path, monkeypatch):
    setup_isolated_store(tmp_path, monkeypatch)

    free = monetization.get_subscription(101)
    assert free["plan_id"] == "free"
    assert free["billing_mode"] == "demo"
    assert free["usage"]["monthly_limit"] == 50

    pro = monetization.set_demo_plan(101, "pro")
    assert pro["plan_id"] == "pro"
    assert pro["plan"]["price"] == 499
    assert pro["usage"]["monthly_limit"] == 1000


def test_monthly_usage_is_counted(tmp_path, monkeypatch):
    setup_isolated_store(tmp_path, monkeypatch)

    monetization.record_ai_usage(202)
    monetization.record_ai_usage(202)
    usage = monetization.get_subscription(202)["usage"]
    assert usage["ai_requests"] == 2
    assert usage["remaining"] == 48


def test_sarvam_key_is_encrypted_masked_and_removable(tmp_path, monkeypatch):
    setup_isolated_store(tmp_path, monkeypatch)
    secret = "sarvam-private-test-key"

    monetization.save_sarvam_key(303, secret)
    assert monetization.get_sarvam_key(303) == secret
    status = monetization.sarvam_key_status(303)
    assert status["configured"] is True
    assert status["masked_key"].endswith(secret[-4:])

    with auth._db() as conn:
        stored = conn.execute(
            "SELECT key_ciphertext FROM user_sarvam_keys WHERE github_id=?",
            (303,),
        ).fetchone()["key_ciphertext"]
    assert secret not in stored

    monetization.delete_sarvam_key(303)
    assert monetization.get_sarvam_key(303) == ""
    assert monetization.sarvam_key_status(303)["configured"] is False
