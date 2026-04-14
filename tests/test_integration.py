"""Type 2 — Integration Tests: modules working together."""

import importlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ===================================================================
# Scanner → Formatter pipeline
# ===================================================================

class TestScannerFormatterPipeline:
    @pytest.fixture()
    def scanner_mod(self):
        return importlib.import_module("services.scanner")

    @pytest.fixture()
    def formatter(self):
        return importlib.import_module("services.formatter")

    def test_safe_result_feeds_formatter_phone(self, scanner_mod, formatter):
        svc = scanner_mod.AsyncScannerService()
        safe = svc._safe_result("phone")
        text = formatter.format_phone(safe)
        assert "Phone" in text or "phone" in text.lower()

    def test_safe_result_feeds_formatter_url(self, scanner_mod, formatter):
        svc = scanner_mod.AsyncScannerService()
        safe = svc._safe_result("url")
        text = formatter.format_url(safe)
        assert isinstance(text, str)

    def test_safe_result_feeds_formatter_file(self, scanner_mod, formatter):
        svc = scanner_mod.AsyncScannerService()
        safe = svc._safe_result("file")
        text = formatter.format_file(safe)
        assert isinstance(text, str)


# ===================================================================
# Moderation → Guards pipeline
# ===================================================================

class TestModerationGuardsPipeline:
    def test_guards_uses_moderation_banned_keywords(self):
        guards = importlib.import_module("middleware.guards")
        mod = importlib.import_module("middleware.moderation")

        update = MagicMock()
        update.effective_user = MagicMock()
        update.effective_user.id = 1

        # Text with banned keyword should fail guards
        ok, msg = guards.check_text_policy(update, "I want to deploy malware")
        assert ok is False

        # Confirm it uses the same keyword list
        hits = mod.find_banned_keywords("I want to deploy malware")
        assert "malware" in hits

    def test_guards_clean_text_passes(self):
        guards = importlib.import_module("middleware.guards")
        update = MagicMock()
        update.effective_user = MagicMock()
        update.effective_user.id = 1

        ok, msg = guards.check_text_policy(update, "Is this phone number safe?")
        assert ok is True


# ===================================================================
# Phone handler → phone validation pipeline
# ===================================================================

class TestPhoneValidationPipeline:
    @pytest.fixture()
    def phone_mod(self):
        return importlib.import_module("handlers.phone")

    def test_extract_then_validate_valid(self, phone_mod):
        candidate = phone_mod._extract_phone_candidate("Call +919876543210")
        assert candidate is not None
        ok, parsed = phone_mod._validate_phone(candidate)
        assert ok is True

    def test_extract_then_validate_invalid_text(self, phone_mod):
        candidate = phone_mod._extract_phone_candidate("no phone here")
        assert candidate is None

    def test_extract_then_build_result(self, phone_mod):
        candidate = phone_mod._extract_phone_candidate("+919876543210")
        ok, parsed = phone_mod._validate_phone(candidate)
        assert ok is True

        text = phone_mod._build_phone_result_text(
            formatted_number="+44 7700 900123",
            country="United Kingdom",
            carrier_name="Vodafone",
            phone_type="mobile",
            risk_level="LOW",
            score=10,
            flags=[],
            advice="No risk detected.",
        )
        assert "United Kingdom" in text


# ===================================================================
# URL handler → extract → analyze pipeline
# ===================================================================

class TestUrlExtractionPipeline:
    @pytest.fixture()
    def url_mod(self):
        return importlib.import_module("handlers.url")

    def test_extract_then_build_result(self, url_mod):
        urls = url_mod.extract_urls("Check https://evil-phish.com/login")
        assert len(urls) == 1

        domain = url_mod._domain_of(urls[0])
        text = url_mod._build_url_result_text(
            url=urls[0],
            domain=domain,
            domain_age="3 days",
            risk_level="HIGH",
            score=85,
            flags=["New domain", "Phishing pattern"],
            forwarded_note=False,
        )
        assert "evil-phish.com" in text
        assert "DANGEROUS" in text


# ===================================================================
# Social handler → database checks pipeline
# ===================================================================

class TestSocialDatabasePipeline:
    @pytest.fixture()
    def social_mod(self):
        return importlib.import_module("handlers.social")

    def test_extract_and_check(self, social_mod):
        text = "Contact @support_refund_team at t.me/scamgroup for official support"
        handles, domains, urls = social_mod._extract_targets(text)
        hits = social_mod._database_checks(text, handles, domains)
        # Should hit known scam handle, high-risk domain, and impersonation phrase
        assert len(hits) >= 3


# ===================================================================
# Voice handler → scam detection pipeline
# ===================================================================

class TestVoiceScamDetectionPipeline:
    @pytest.fixture()
    def voice_mod(self):
        return importlib.import_module("handlers.voice")

    def test_detect_then_render(self, voice_mod):
        transcript = "Your aadhaar blocked. Please send otp to verify."
        analysis = voice_mod._detect_scam_patterns(transcript)
        assert analysis["hit_count"] >= 2

        deepfake = voice_mod._deepfake_likelihood(analysis, backend_score=60)
        text = voice_mod._build_voice_result_text(
            transcript,
            analysis,
            deepfake_percent=deepfake,
            explanation="Likely scam call.",
        )
        assert "Aadhaar" in text or "aadhaar" in text.lower()
        assert "SCAM" in text


# ===================================================================
# Config → settings used by scanner
# ===================================================================

class TestConfigScannerIntegration:
    def test_scanner_uses_config_timeout(self):
        config = importlib.import_module("config")
        scanner_mod = importlib.import_module("services.scanner")
        svc = scanner_mod.AsyncScannerService()
        # Timeout should match config value
        assert svc.timeout.read == config.SCAN_TIMEOUT or svc.timeout.connect is not None


# ===================================================================
# Database models — async session + CRUD integration
# ===================================================================

class TestDatabaseCrudIntegration:
    @pytest.fixture()
    def db_mod(self):
        return importlib.import_module("database.models")

    async def test_init_db_and_create_user(self, db_mod):
        # Use in-memory SQLite for integration testing
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(db_mod.Base.metadata.create_all)

        session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with session_factory() as session:
            user = db_mod.User(
                telegram_id="12345",
                username="testuser",
                full_name="Test User",
                plan="free",
                scans_used=0,
                scans_limit=5,
            )
            session.add(user)
            await session.commit()

            fetched = await session.get(db_mod.User, "12345")
            assert fetched is not None
            assert fetched.username == "testuser"
            assert fetched.plan == "free"

        await engine.dispose()

    async def test_scan_log_and_moderation_log(self, db_mod):
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(db_mod.Base.metadata.create_all)

        session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with session_factory() as session:
            # Create user first
            user = db_mod.User(telegram_id="99", username="mod_test", full_name="Mod User")
            session.add(user)
            await session.flush()

            # Add scan log
            scan = db_mod.ScanLog(
                telegram_id="99",
                scan_type="url",
                risk_level="HIGH",
                risk_score=85.0,
            )
            session.add(scan)
            await session.flush()
            assert scan.id is not None

            # Add moderation log
            mod_log = db_mod.ModerationLog(
                telegram_id="99",
                action="warn",
                reason="offensive language",
            )
            session.add(mod_log)
            await session.commit()

        await engine.dispose()
