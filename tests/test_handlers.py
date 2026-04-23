"""Type 3 — Handler Tests: bot command handlers with mocked Telegram objects."""

import importlib
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers to build mock Telegram Update / Context objects
# ---------------------------------------------------------------------------

def _make_user(user_id: int = 42, username: str = "testuser", first_name: str = "Test"):
    user = MagicMock()
    user.id = user_id
    user.username = username
    user.first_name = first_name
    return user


def _make_message(text: str = "", user_id: int = 42):
    msg = MagicMock()
    msg.text = text
    msg.caption = None
    msg.reply_text = AsyncMock()
    msg.delete = AsyncMock()
    msg.forward_origin = None
    msg.photo = None
    msg.document = None
    msg.voice = None
    msg.audio = None
    return msg


def _make_update(text: str = "", user_id: int = 42, callback_data: str | None = None):
    update = MagicMock()
    update.effective_user = _make_user(user_id)
    update.effective_chat = MagicMock()
    update.effective_chat.id = user_id
    update.effective_message = _make_message(text, user_id)
    if callback_data is not None:
        query = MagicMock()
        query.data = callback_data
        query.answer = AsyncMock()
        query.message = _make_message()
        query.edit_message_text = AsyncMock()
        update.callback_query = query
        update.message = None
    else:
        update.callback_query = None
        update.message = update.effective_message
        update.message.text = text
    return update


def _make_context(scan_mode: str | None = None, args: list[str] | None = None):
    ctx = MagicMock()
    ctx.user_data = {}
    if scan_mode:
        ctx.user_data["scan_mode"] = scan_mode
    ctx.args = args or []
    ctx.bot = MagicMock()
    ctx.bot.send_message = AsyncMock()
    ctx.bot.send_chat_action = AsyncMock()
    return ctx


# ===================================================================
# handlers/start.py
# ===================================================================

class TestStartHandler:
    """Tests for start_command."""

    @pytest.fixture(autouse=True)
    def _patch_db(self, monkeypatch):
        monkeypatch.setattr("handlers.start.engine", MagicMock())
        monkeypatch.setattr("handlers.start.SessionLocal", MagicMock())

    @pytest.fixture()
    def start_mod(self):
        return importlib.import_module("handlers.start")

    async def test_start_new_user(self, start_mod, monkeypatch):
        monkeypatch.setattr(start_mod, "_find_user", lambda uid: None)
        created = MagicMock(plan="free", scans_used=0, first_name="Test")
        monkeypatch.setattr(start_mod, "_create_user", lambda uid, un, fn: created)

        update = _make_update("/start")
        ctx = _make_context()
        await start_mod.start_command(update, ctx)

        update.message.reply_text.assert_called_once()
        call_text = update.message.reply_text.call_args[0][0]
        assert "CyberGuard AI" in call_text

    async def test_start_existing_user(self, start_mod, monkeypatch):
        existing = MagicMock(plan="free", scans_used=2, first_name="Alice")
        monkeypatch.setattr(start_mod, "_find_user", lambda uid: existing)

        update = _make_update("/start")
        ctx = _make_context()
        await start_mod.start_command(update, ctx)

        call_text = update.message.reply_text.call_args[0][0]
        assert "Welcome back" in call_text

    async def test_start_no_message_is_noop(self, start_mod):
        update = MagicMock()
        update.message = None
        update.effective_user = _make_user()
        ctx = _make_context()
        await start_mod.start_command(update, ctx)
        # Should silently return without error

    async def test_help_command(self, start_mod):
        update = _make_update("/help")
        ctx = _make_context()
        await start_mod.help_command(update, ctx)

        call_text = update.message.reply_text.call_args[0][0]
        assert "CyberGuard AI Help" in call_text
        assert "/start" in call_text

    async def test_agreement_button_handler(self, start_mod, monkeypatch):
        agreed_user = MagicMock(plan="free", scans_used=0, first_name="Bob")
        monkeypatch.setattr(start_mod, "_mark_terms_agreed", lambda uid: agreed_user)

        update = _make_update(callback_data="agree_terms")
        ctx = _make_context()
        await start_mod.agreement_button_handler(update, ctx)

        update.callback_query.answer.assert_awaited_once()
        update.callback_query.edit_message_text.assert_awaited_once()

    async def test_start_menu_callback_sets_scan_mode(self, start_mod):
        for mode_data, expected_mode in [
            ("scan_phone", "phone"),
            ("scan_url", "url"),
            ("scan_social", "social"),
            ("scan_file", "file"),
            ("scan_image", "image"),
            ("scan_voice", "voice"),
        ]:
            update = _make_update(callback_data=mode_data)
            ctx = _make_context()
            await start_mod.start_menu_callback_handler(update, ctx)
            assert ctx.user_data["scan_mode"] == expected_mode

    async def test_plan_remaining(self, start_mod):
        assert start_mod._plan_remaining("free", 0) == 5
        assert start_mod._plan_remaining("free", 5) == 0
        assert start_mod._plan_remaining("pro", 100) == 400
        assert start_mod._plan_remaining("full", 1000) == 4000


# ===================================================================
# handlers/phone.py  (pure utility functions)
# ===================================================================

class TestPhoneHandler:
    @pytest.fixture()
    def phone_mod(self):
        return importlib.import_module("handlers.phone")

    def test_normalize_candidate(self, phone_mod):
        assert phone_mod._normalize_candidate("+44 7700 900 123") == "+447700900123"
        assert phone_mod._normalize_candidate("(91) 98765-43210") == "919876543210"

    def test_extract_phone_candidate_valid(self, phone_mod):
        assert phone_mod._extract_phone_candidate("Call me at +447700900123 please") == "+447700900123"

    def test_extract_phone_candidate_india_local(self, phone_mod):
        assert phone_mod._extract_phone_candidate("9876543210") == "9876543210"

    def test_extract_phone_candidate_none(self, phone_mod):
        assert phone_mod._extract_phone_candidate("just some random text") is None

    def test_validate_phone_valid(self, phone_mod):
        ok, parsed = phone_mod._validate_phone("+919876543210")
        assert ok is True
        assert parsed is not None

    def test_validate_phone_invalid(self, phone_mod):
        ok, parsed = phone_mod._validate_phone("+00000000000")
        assert ok is False

    def test_phone_type_label(self, phone_mod):
        import phonenumbers
        parsed = phonenumbers.parse("+447700900123", None)
        label = phone_mod._phone_type_label(parsed)
        assert label in ("mobile", "landline", "mobile/landline", "VoIP", "unknown")

    def test_risk_meter_boundaries(self, phone_mod):
        assert len(phone_mod._risk_meter(0)) == 10
        assert phone_mod._risk_meter(0) == "░" * 10
        assert phone_mod._risk_meter(100) == "█" * 10
        assert "█" in phone_mod._risk_meter(50)

    def test_risk_label(self, phone_mod):
        assert "HIGH" in phone_mod._risk_label("HIGH")
        assert "MEDIUM" in phone_mod._risk_label("MEDIUM")
        assert "LOW" in phone_mod._risk_label("LOW")
        assert "UNKNOWN" in phone_mod._risk_label("whatever")

    def test_build_phone_result_text(self, phone_mod):
        text = phone_mod._build_phone_result_text(
            formatted_number="+44 7700 900123",
            country="United Kingdom",
            carrier_name="Vodafone",
            phone_type="mobile",
            risk_level="HIGH",
            score=85,
            flags=["Suspicious carrier"],
            advice="Block this number.",
        )
        assert "United Kingdom" in text
        assert "Vodafone" in text
        assert "HIGH" in text

    def test_result_buttons_high_risk(self, phone_mod):
        markup = phone_mod._result_buttons(is_high_risk=True)
        # High risk should include both "Full Report" and "File Complaint"
        flat = str(markup)
        assert "Full Report" in flat
        assert "File Complaint" in flat

    def test_result_buttons_low_risk(self, phone_mod):
        markup = phone_mod._result_buttons(is_high_risk=False)
        flat = str(markup)
        assert "Full Report" in flat


# ===================================================================
# handlers/url.py (pure utility functions)
# ===================================================================

class TestUrlHandler:
    @pytest.fixture()
    def url_mod(self):
        return importlib.import_module("handlers.url")

    def test_extract_urls_http(self, url_mod):
        urls = url_mod.extract_urls("Check https://example.com/path and http://evil.org")
        assert len(urls) == 2

    def test_extract_urls_bare_domain(self, url_mod):
        urls = url_mod.extract_urls("Visit evil.com/login now")
        assert any("evil.com" in u for u in urls)

    def test_extract_urls_no_urls(self, url_mod):
        assert url_mod.extract_urls("just some normal text") == []

    def test_extract_urls_dedup(self, url_mod):
        urls = url_mod.extract_urls("https://example.com/page https://example.com/page")
        # http URL is deduped, but bare domain variant may also be extracted
        http_urls = [u for u in urls if u.startswith("http")]
        assert len(http_urls) == 1

    def test_domain_of(self, url_mod):
        assert url_mod._domain_of("https://example.com/path") == "example.com"
        assert url_mod._domain_of("evil.org/login") == "evil.org"

    def test_shorten_url(self, url_mod):
        short = url_mod._shorten_url("https://example.com", max_len=100)
        assert short == "https://example.com"
        long_url = "https://example.com/" + "a" * 100
        assert len(url_mod._shorten_url(long_url)) <= 52

    def test_risk_level_text(self, url_mod):
        assert "DANGEROUS" in url_mod._risk_level_text("HIGH")
        assert "SUSPICIOUS" in url_mod._risk_level_text("MEDIUM")
        assert "LOW" in url_mod._risk_level_text("LOW")

    def test_risk_bar(self, url_mod):
        assert url_mod._risk_bar(0) == "░" * 10
        assert url_mod._risk_bar(100) == "█" * 10

    def test_extract_domain_age(self, url_mod):
        result = url_mod._extract_domain_age(["Registered 3 days ago"])
        assert "3" in result and "day" in result
        assert url_mod._extract_domain_age(["No info"]) == "Unknown"

    def test_build_url_result_text(self, url_mod):
        text = url_mod._build_url_result_text(
            url="https://evil.com",
            domain="evil.com",
            domain_age="2 days",
            risk_level="HIGH",
            score=90,
            flags=["Phishing pattern"],
            forwarded_note=True,
        )
        assert "Forwarded message" in text
        assert "evil.com" in text

    def test_next_report_id_increments(self, url_mod):
        ctx = _make_context()
        id1 = url_mod._next_report_id(ctx)
        id2 = url_mod._next_report_id(ctx)
        assert id2 == id1 + 1


# ===================================================================
# handlers/file.py (pure utility functions)
# ===================================================================

class TestFileHandler:
    @pytest.fixture()
    def file_mod(self):
        return importlib.import_module("handlers.file")

    def test_format_size(self, file_mod):
        assert "MB" in file_mod._format_size(2_000_000)
        assert "KB" in file_mod._format_size(2048)
        assert "B" in file_mod._format_size(500)

    def test_shorten_hash(self, file_mod):
        full = "a" * 64
        short = file_mod._shorten_hash(full)
        assert "..." in short
        assert short.startswith("a" * 12)

    def test_risk_label(self, file_mod):
        assert "MALICIOUS" in file_mod._risk_label("HIGH")
        assert "SUSPICIOUS" in file_mod._risk_label("MEDIUM")
        assert "CLEAN" in file_mod._risk_label("LOW")

    def test_build_file_result_text(self, file_mod):
        text = file_mod._build_file_result_text(
            filename="test.exe",
            size_bytes=1_500_000,
            sha256="a" * 64,
            risk_level="HIGH",
            threats=["Trojan.GenericKD"],
            yara_hits=2,
            vt_hits=15,
            vt_total=70,
        )
        assert "test.exe" in text
        assert "MALICIOUS" in text
        assert "15/70" in text


# ===================================================================
# handlers/social.py (pure utility functions)
# ===================================================================

class TestSocialHandler:
    @pytest.fixture()
    def social_mod(self):
        return importlib.import_module("handlers.social")

    def test_looks_like_social_text(self, social_mod):
        assert social_mod._looks_like_social_text("Follow @scammer123") is True
        assert social_mod._looks_like_social_text("Check instagram.com/user") is True
        assert social_mod._looks_like_social_text("hello world") is False

    def test_extract_targets_handle(self, social_mod):
        handles, domains, urls = social_mod._extract_targets("From @scam_user on telegram")
        assert "scam_user" in handles

    def test_extract_targets_url(self, social_mod):
        handles, domains, urls = social_mod._extract_targets("Check https://facebook.com/scammer")
        assert len(urls) >= 1
        assert any("facebook" in d for d in domains)

    def test_database_checks_known_handle(self, social_mod):
        hits = social_mod._database_checks(
            "From @support_refund_team",
            ["support_refund_team"],
            [],
        )
        assert any("Known Scam" in h["database"] for h in hits)

    def test_database_checks_high_risk_domain(self, social_mod):
        hits = social_mod._database_checks(
            "Join t.me/scamgroup",
            [],
            ["t.me"],
        )
        assert any("High-Risk" in h["database"] for h in hits)

    def test_database_checks_impersonation(self, social_mod):
        hits = social_mod._database_checks(
            "This is official support for your account verification",
            [],
            [],
        )
        assert len(hits) >= 1

    def test_database_checks_financial_scam(self, social_mod):
        hits = social_mod._database_checks(
            "Please send otp for instant loan approval",
            [],
            [],
        )
        assert len(hits) >= 2

    def test_risk_level_thresholds(self, social_mod):
        assert social_mod._risk_level(80) == "HIGH"
        assert social_mod._risk_level(50) == "MEDIUM"
        assert social_mod._risk_level(20) == "LOW"

    def test_render_result(self, social_mod):
        text = social_mod._render_result(
            handles=["scammer"],
            domains=["t.me"],
            db_hits=[{"database": "Test DB", "match": "@scammer", "reason": "Known scam"}],
            final_score=75,
            final_risk="HIGH",
        )
        assert "HIGH" in text
        assert "@scammer" in text

    def test_is_master_plan(self, social_mod):
        assert social_mod._is_master_plan("full") is True
        assert social_mod._is_master_plan("master") is True
        assert social_mod._is_master_plan("enterprise") is True
        assert social_mod._is_master_plan("pro") is False

    def test_render_result_with_agentic_summary(self, social_mod):
        text = social_mod._render_result(
            handles=["scammer"],
            domains=["t.me"],
            db_hits=[],
            final_score=70,
            final_risk="HIGH",
            plan_name="full",
            agentic_summary="Likely staged impersonation plus payment extraction flow.",
        )
        assert "Master Agentic Chat Intel" in text
        assert "Plan: Full" in text


# ===================================================================
# handlers/voice.py (pure utility functions)
# ===================================================================

class TestVoiceHandler:
    @pytest.fixture()
    def voice_mod(self):
        return importlib.import_module("handlers.voice")

    def test_detect_scam_patterns_india(self, voice_mod):
        result = voice_mod._detect_scam_patterns("Your aadhaar blocked please send otp")
        assert result["hit_count"] >= 2
        assert "Aadhaar Blocked Scam" in result["dominant_scam_type"] or result["hit_count"] > 0

    def test_detect_scam_patterns_uk(self, voice_mod):
        result = voice_mod._detect_scam_patterns("This is hmrc tax refund notification")
        assert result["hit_count"] >= 1

    def test_detect_scam_patterns_clean(self, voice_mod):
        result = voice_mod._detect_scam_patterns("Hello, how are you doing today?")
        assert result["hit_count"] == 0
        assert result["confidence"] == 0

    def test_deepfake_likelihood_range(self, voice_mod):
        analysis = {"hit_count": 0, "matched_phrases": [], "dominant_scam_type": "None", "confidence": 0}
        dl = voice_mod._deepfake_likelihood(analysis, 50)
        assert 12 <= dl <= 95

    def test_extract_extension(self, voice_mod):
        assert voice_mod._extract_extension("audio.mp3", None, False) == "mp3"
        assert voice_mod._extract_extension(None, "audio/mpeg", False) == "mp3"
        assert voice_mod._extract_extension(None, None, True) == "ogg"

    def test_mime_type_for_extension(self, voice_mod):
        assert voice_mod._mime_type_for_extension("mp3") == "audio/mpeg"
        assert voice_mod._mime_type_for_extension("wav") == "audio/wav"

    def test_build_voice_result_text(self, voice_mod):
        analysis = {
            "hit_count": 2,
            "matched_phrases": ["aadhaar blocked", "send otp"],
            "dominant_scam_type": "Aadhaar Blocked Scam",
            "confidence": 56,
        }
        text = voice_mod._build_voice_result_text(
            "your aadhaar is blocked send otp now",
            analysis,
            deepfake_percent=40,
            explanation="Likely phone scam.",
        )
        assert "Aadhaar Blocked Scam" in text
        assert "Deepfake" in text or "deepfake" in text.lower()

    def test_is_master_plan(self, voice_mod):
        assert voice_mod._is_master_plan("full") is True
        assert voice_mod._is_master_plan("master") is True
        assert voice_mod._is_master_plan("enterprise") is True
        assert voice_mod._is_master_plan("free") is False

    def test_build_voice_result_text_with_master_insights(self, voice_mod):
        analysis = {
            "hit_count": 1,
            "matched_phrases": ["send otp"],
            "dominant_scam_type": "OTP Theft",
            "confidence": 35,
        }
        text = voice_mod._build_voice_result_text(
            "please send otp now",
            analysis,
            deepfake_percent=44,
            explanation="Possible coercive scam content.",
            master_insights={
                "threat_story": "Caller used urgency and authority claims to extract OTP.",
                "urgency_score": 81,
                "impersonation_risk": "high",
                "tactics": ["urgency_pressure", "credential_harvest"],
                "next_best_actions": ["Do not share OTP"],
            },
        )
        assert "Master Agentic Voice Intel" in text
        assert "Urgency Score: 81" in text


# ===================================================================
# handlers/image.py (pure utility functions)
# ===================================================================

class TestImageHandler:
    @pytest.fixture()
    def image_mod(self):
        return importlib.import_module("handlers.image")

    def test_format_size(self, image_mod):
        assert "MB" in image_mod._format_size(2_000_000)
        assert "KB" in image_mod._format_size(2048)

    def test_privacy_risk_with_gps(self, image_mod):
        level, msg = image_mod._privacy_risk({"gps_found": True})
        assert level == "HIGH"

    def test_privacy_risk_without_gps(self, image_mod):
        level, msg = image_mod._privacy_risk({"gps_found": False})
        assert level == "LOW"

    def test_estimate_ai_likelihood(self, image_mod):
        result = {"score": 70}
        metadata = {"edited": "Yes"}
        pct = image_mod._estimate_ai_likelihood(result, metadata)
        assert 15 <= pct <= 98

    def test_risk_badge(self, image_mod):
        assert "HIGH" in image_mod._risk_badge("HIGH")
        assert "LOW" in image_mod._risk_badge("LOW")

    def test_build_image_result_text(self, image_mod):
        text = image_mod._build_image_result_text(
            filename="photo.jpg",
            size_bytes=500_000,
            metadata={"format": "JPEG", "device": "iPhone", "taken_at": "2024-01-01", "edited": "No", "gps_found": False, "software": "No"},
            ai_percent=30,
            risk_level="LOW",
            risk_msg="No location metadata.",
            hide_coordinates=True,
        )
        assert "JPEG" in text
        assert "iPhone" in text

    def test_infer_social_footprint_from_filename_and_software(self, image_mod):
        footprint = image_mod._infer_social_footprint(
            filename="instagram_post_2026.jpg",
            caption="my upload",
            metadata={"software": "Instagram", "device": "iPhone"},
            backend_details={},
        )
        assert footprint["public_footprint_likely"] is True
        assert "instagram" in footprint["platforms"]

    def test_build_image_result_includes_social_footprint(self, image_mod):
        text = image_mod._build_image_result_text(
            filename="photo.jpg",
            size_bytes=100_000,
            metadata={"format": "JPEG", "device": "Android", "taken_at": "2024-01-01", "edited": "No", "gps_found": False, "software": "No"},
            ai_percent=20,
            risk_level="LOW",
            risk_msg="No location metadata.",
            hide_coordinates=True,
            social_footprint={"public_footprint_likely": True, "probable_posted_on": "instagram, x/twitter"},
        )
        assert "Social Footprint" in text
        assert "instagram" in text
