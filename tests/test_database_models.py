"""Tests for database models — both app/db and cyberguard-telegram/database."""

import importlib
from datetime import datetime, timezone

import pytest

from app.db.models import Base as AppBase, ScanLog
from app.db.repository import ScanLogRepository
from app.security.compliance import enforce_user_provided_only, hash_content, pseudonymize_user_id


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  app/db/models.py — ScanLog model                                      ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def test_scan_log_table_name():
    assert ScanLog.__tablename__ == "scan_logs"


def test_scan_log_creates_uuid_id():
    log = ScanLog(
        id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        source="telegram",
        content_sha256="abc123",
        risk_level="low",
        score=10,
    )
    assert log.id is not None
    assert len(log.id) == 36  # UUID format


def test_scan_log_accepts_optional_user():
    log = ScanLog(
        source="api",
        pseudonymized_user_id="hashed-id",
        content_sha256="def456",
        risk_level="high",
        score=90,
    )
    assert log.pseudonymized_user_id == "hashed-id"


def test_scan_log_nullable_user():
    log = ScanLog(
        source="telegram",
        content_sha256="ghi789",
        risk_level="medium",
        score=50,
    )
    assert log.pseudonymized_user_id is None


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  app/security/compliance.py                                             ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def test_enforce_user_provided_only_raises_on_no_consent():
    with pytest.raises(ValueError, match="Consent"):
        enforce_user_provided_only("content", consent_confirmed=False)


def test_enforce_user_provided_only_raises_on_empty():
    with pytest.raises(ValueError):
        enforce_user_provided_only("", consent_confirmed=True)


def test_enforce_user_provided_only_raises_on_whitespace():
    with pytest.raises(ValueError):
        enforce_user_provided_only("   ", consent_confirmed=True)


def test_enforce_user_provided_only_passes():
    enforce_user_provided_only("Valid content", consent_confirmed=True)


def test_pseudonymize_user_id_deterministic():
    h1 = pseudonymize_user_id("user-99")
    h2 = pseudonymize_user_id("user-99")
    assert h1 == h2
    assert len(h1) == 64


def test_pseudonymize_user_id_none():
    assert pseudonymize_user_id(None) is None


def test_pseudonymize_user_id_different_inputs():
    h1 = pseudonymize_user_id("alice")
    h2 = pseudonymize_user_id("bob")
    assert h1 != h2


def test_hash_content_deterministic():
    assert hash_content("test") == hash_content("test")
    assert len(hash_content("test")) == 64


def test_hash_content_different():
    assert hash_content("a") != hash_content("b")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  cyberguard-telegram/database/models.py — Bot-side models              ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.fixture()
def bot_models():
    return importlib.import_module("database.models")


def test_user_model_table(bot_models):
    assert bot_models.User.__tablename__ == "users"


def test_scan_log_bot_model_table(bot_models):
    assert bot_models.ScanLog.__tablename__ == "scan_logs"


def test_moderation_log_table(bot_models):
    assert bot_models.ModerationLog.__tablename__ == "moderation_logs"


def test_bot_user_compat_alias(bot_models):
    # BotUser is a backward-compat alias
    assert hasattr(bot_models, "BotUser")


def test_user_moderation_compat_alias(bot_models):
    assert hasattr(bot_models, "UserModeration")


def test_init_db_callable(bot_models):
    assert callable(bot_models.init_db)


def test_session_scope_callable(bot_models):
    assert callable(bot_models.session_scope)


def test_get_or_create_user_callable(bot_models):
    assert callable(bot_models.get_or_create_user)


def test_increment_scan_count_callable(bot_models):
    assert callable(bot_models.increment_scan_count)


def test_add_warning_callable(bot_models):
    assert callable(bot_models.add_warning)


def test_ban_user_callable(bot_models):
    assert callable(bot_models.ban_user)


def test_reset_monthly_scans_callable(bot_models):
    assert callable(bot_models.reset_monthly_scans)


def test_log_scan_callable(bot_models):
    assert callable(bot_models.log_scan)
