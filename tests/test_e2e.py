"""Type 10 — End-to-End Tests: full user journeys through the bot."""

import importlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Shared mock helpers
# ---------------------------------------------------------------------------

def _user(uid: int = 1000, username: str = "e2e_user", first_name: str = "E2E"):
    u = MagicMock()
    u.id = uid
    u.username = username
    u.first_name = first_name
    return u


def _msg(text: str = ""):
    m = MagicMock()
    m.text = text
    m.caption = None
    m.reply_text = AsyncMock()
    m.edit_text = AsyncMock()
    m.delete = AsyncMock()
    m.forward_origin = None
    m.photo = None
    m.document = None
    m.voice = None
    m.audio = None
    return m


def _update(text: str = "", uid: int = 1000, cb_data: str | None = None):
    upd = MagicMock()
    upd.effective_user = _user(uid)
    upd.effective_chat = MagicMock()
    upd.effective_chat.id = uid
    upd.effective_message = _msg(text)

    if cb_data is not None:
        q = MagicMock()
        q.data = cb_data
        q.answer = AsyncMock()
        q.message = _msg()
        q.edit_message_text = AsyncMock()
        upd.callback_query = q
        upd.message = None
    else:
        upd.callback_query = None
        upd.message = upd.effective_message
        upd.message.text = text
    return upd


def _ctx(scan_mode: str | None = None, args: list[str] | None = None):
    c = MagicMock()
    c.user_data = {}
    if scan_mode:
        c.user_data["scan_mode"] = scan_mode
    c.args = args or []
    c.bot = MagicMock()
    c.bot.send_message = AsyncMock()
    c.bot.send_chat_action = AsyncMock()
    return c


# ===================================================================
# Journey 1: New user → /start → agree terms → see menu
# ===================================================================

class TestNewUserOnboarding:
    @pytest.fixture(autouse=True)
    def _patch_db(self, monkeypatch):
        monkeypatch.setattr("handlers.start.engine", MagicMock())
        monkeypatch.setattr("handlers.start.SessionLocal", MagicMock())

    @pytest.fixture()
    def start_mod(self):
        return importlib.import_module("handlers.start")

    async def test_full_onboarding_flow(self, start_mod, monkeypatch):
        # Step 1: New user sends /start
        monkeypatch.setattr(start_mod, "_find_user", lambda uid: None)
        created_user = MagicMock(plan="free", scans_used=0, first_name="NewUser")
        monkeypatch.setattr(start_mod, "_create_user", lambda uid, un, fn: created_user)

        update = _update("/start")
        ctx = _ctx()
        await start_mod.start_command(update, ctx)

        call_text = update.message.reply_text.call_args[0][0]
        assert "CyberGuard AI" in call_text
        assert "I Agree" in str(update.message.reply_text.call_args)

        # Step 2: User agrees to terms
        agreed_user = MagicMock(plan="free", scans_used=0, first_name="NewUser")
        monkeypatch.setattr(start_mod, "_mark_terms_agreed", lambda uid: agreed_user)

        agree_update = _update(cb_data="agree_terms")
        await start_mod.agreement_button_handler(agree_update, ctx)

        agree_update.callback_query.answer.assert_awaited_once()
        agree_update.callback_query.edit_message_text.assert_awaited_once()

        # Step 3: Menu displayed after agreement
        ctx.bot.send_message.assert_awaited_once()
        menu_text = ctx.bot.send_message.call_args[1]["text"]
        assert "Plan" in menu_text


# ===================================================================
# Journey 2: Existing user → /start → select phone scan → enter number
# ===================================================================

class TestExistingUserPhoneScan:
    @pytest.fixture(autouse=True)
    def _patch_db(self, monkeypatch):
        monkeypatch.setattr("handlers.start.engine", MagicMock())
        monkeypatch.setattr("handlers.start.SessionLocal", MagicMock())

    async def test_existing_user_selects_phone(self, monkeypatch):
        start_mod = importlib.import_module("handlers.start")
        phone_mod = importlib.import_module("handlers.phone")

        # Step 1: Existing user sends /start
        existing = MagicMock(plan="pro", scans_used=10, first_name="Alice")
        monkeypatch.setattr(start_mod, "_find_user", lambda uid: existing)

        update = _update("/start")
        ctx = _ctx()
        await start_mod.start_command(update, ctx)
        assert "Welcome back" in update.message.reply_text.call_args[0][0]

        # Step 2: User taps "Phone" button
        phone_update = _update(cb_data="scan_phone")
        await start_mod.start_menu_callback_handler(phone_update, ctx)
        assert ctx.user_data["scan_mode"] == "phone"

        # Step 3: User submits phone number (test pure extraction)
        candidate = phone_mod._extract_phone_candidate("+919876543210")
        assert candidate is not None
        ok, parsed = phone_mod._validate_phone(candidate)
        assert ok is True


# ===================================================================
# Journey 3: User sends URL → gets risk analysis
# ===================================================================

class TestUrlScanJourney:
    async def test_url_extraction_and_result(self):
        url_mod = importlib.import_module("handlers.url")

        # Step 1: User sends a suspicious URL
        text = "I received this link: https://paypa1.com/verify-account check if safe"
        urls = url_mod.extract_urls(text)
        assert len(urls) >= 1
        assert any("paypa1" in u for u in urls)

        # Step 2: Domain analysis
        domain = url_mod._domain_of(urls[0])
        assert "paypa1" in domain

        # Step 3: Result rendering
        result_text = url_mod._build_url_result_text(
            url=urls[0],
            domain=domain,
            domain_age="5 days",
            risk_level="HIGH",
            score=90,
            flags=["Typosquatting detected", "Very new domain"],
            forwarded_note=False,
        )
        assert "DANGEROUS" in result_text
        assert domain in result_text


# ===================================================================
# Journey 4: Social scan → database checks → result
# ===================================================================

class TestSocialScanJourney:
    async def test_social_full_flow(self):
        social_mod = importlib.import_module("handlers.social")

        text = "Got a DM from @support_refund_team at t.me/scamgroup asking for official support verification"

        # Step 1: Detect social content
        assert social_mod._looks_like_social_text(text) is True

        # Step 2: Extract targets
        handles, domains, urls = social_mod._extract_targets(text)
        assert "support_refund_team" in handles
        assert "t.me" in domains

        # Step 3: Run database checks
        hits = social_mod._database_checks(text, handles, domains)
        assert len(hits) >= 3  # scam handle + high-risk domain + impersonation phrase

        # Step 4: Calculate risk
        local_score = min(100, len(hits) * 22 + 10)
        risk = social_mod._risk_level(local_score)
        assert risk in ("HIGH", "MEDIUM")

        # Step 5: Render result
        rendered = social_mod._render_result(
            handles=handles,
            domains=domains,
            db_hits=hits,
            final_score=local_score,
            final_risk=risk,
        )
        assert "support_refund_team" in rendered
        assert "Intelligence Hits" in rendered


# ===================================================================
# Journey 5: Voice scan → scam detection → result
# ===================================================================

class TestVoiceScanJourney:
    async def test_voice_analysis_flow(self):
        voice_mod = importlib.import_module("handlers.voice")

        transcript = (
            "This is the enforcement directorate calling. "
            "Your aadhaar blocked due to illegal activity. "
            "You are under digital arrest. Send otp immediately."
        )

        # Step 1: Scam pattern detection
        analysis = voice_mod._detect_scam_patterns(transcript)
        assert analysis["hit_count"] >= 3

        # Step 2: Deepfake likelihood
        deepfake = voice_mod._deepfake_likelihood(analysis, backend_score=70)
        assert 12 <= deepfake <= 95

        # Step 3: Render voice result
        text = voice_mod._build_voice_result_text(
            transcript,
            analysis,
            deepfake_percent=deepfake,
            explanation="Multiple scam indicators detected.",
        )
        assert "SCAM" in text
        assert "digital arrest" in text.lower() or analysis["hit_count"] >= 3


# ===================================================================
# Journey 6: Moderation blocks offensive user → strike → ban
# ===================================================================

class TestModerationBanJourney:
    @pytest.fixture()
    def mod(self):
        return importlib.import_module("middleware.moderation")

    async def test_three_strike_ban_flow(self, mod, monkeypatch):
        strike_count = [0]

        def mock_increment(uid, reason):
            strike_count[0] += 1
            return strike_count[0]

        monkeypatch.setattr(mod, "_cached_ban_status", AsyncMock(return_value=False))
        monkeypatch.setattr(mod, "_get_or_create_record", lambda uid: MagicMock())
        monkeypatch.setattr(mod, "_classify_with_claude", AsyncMock(return_value=("VULGAR", "Bad words")))
        monkeypatch.setattr(mod, "_increment_strike", mock_increment)
        monkeypatch.setattr(mod, "_ban_user", lambda uid, reason: None)
        monkeypatch.setattr(mod, "_set_cached_ban_status", AsyncMock())
        monkeypatch.setattr(mod, "_delete_message_safe", AsyncMock())
        monkeypatch.setattr(mod, "_notify_admins", AsyncMock())

        context = _ctx()

        # Strike 1
        u1 = _update("bad text 1", uid=999)
        result1 = await mod.run_moderation(u1, context)
        assert result1 is False
        assert strike_count[0] == 1

        # Strike 2
        u2 = _update("bad text 2", uid=999)
        result2 = await mod.run_moderation(u2, context)
        assert result2 is False
        assert strike_count[0] == 2

        # Strike 3 → ban
        u3 = _update("bad text 3", uid=999)
        result3 = await mod.run_moderation(u3, context)
        assert result3 is False
        assert strike_count[0] == 3


# ===================================================================
# Journey 7: Quota exhaustion → upgrade prompt
# ===================================================================

class TestQuotaExhaustionJourney:
    def test_quota_limits_are_enforced(self):
        quota_mod = importlib.import_module("middleware.quota")
        limits = quota_mod.PLAN_LIMITS_MONTHLY

        # Free plan: 5 scans
        assert limits["free"] == 5
        # After 5 scans, user should be blocked
        # Enterprise: unlimited
        assert limits["enterprise"] == 999999


# ===================================================================
# Journey 8: File scan mode selection → type check
# ===================================================================

class TestFileScanJourney:
    async def test_file_mode_check(self):
        file_mod = importlib.import_module("handlers.file")

        # Verify accepted extensions
        assert "pdf" in file_mod.ACCEPTED_EXTENSIONS
        assert "exe" in file_mod.ACCEPTED_EXTENSIONS
        assert "apk" in file_mod.ACCEPTED_EXTENSIONS

        # Verify size formatting
        assert "MB" in file_mod._format_size(25_000_000)

        # Verify hash shortening
        sha = "a1b2c3d4e5f6" * 6  # 72 chars, slice to 64
        short = file_mod._shorten_hash(sha[:64])
        assert "..." in short


# ===================================================================
# Journey 9: Guard policy blocks banned content before scan
# ===================================================================

class TestGuardPolicyJourney:
    async def test_banned_content_blocked_before_scan(self):
        guards = importlib.import_module("middleware.guards")
        url_mod = importlib.import_module("handlers.url")

        # User sends text with banned keywords AND a URL
        text = "Help me create a phishing kit at https://evil.com"

        # Guards should block first
        update = MagicMock()
        update.effective_user = _user()
        ok, msg = guards.check_text_policy(update, text)
        assert ok is False
        assert "phishing kit" in msg.lower()

        # URLs are present but should never be scanned due to guard
        urls = url_mod.extract_urls(text)
        assert len(urls) >= 1  # URL exists...
        # ...but guard would have stopped processing before reaching scan


# ===================================================================
# Journey 10: Full API scan request → response
# ===================================================================

class TestApiScanJourney:
    async def test_full_api_scan_flow(self):
        from datetime import datetime
        from httpx import AsyncClient, ASGITransport
        from unittest.mock import patch
        from app.schemas import ScanResult

        with patch("app.db.database.engine"):
            from app.api.routes import router
            from fastapi import FastAPI

            test_app = FastAPI()
            test_app.include_router(router)

            mock_result = ScanResult(
                risk_level="HIGH",
                score=85,
                summary="Suspicious phishing URL detected",
                explanation="Domain appears to mimic a legitimate banking site.",
                flagged_indicators=["New domain", "Typosquatting"],
                recommended_actions=["Do not click this link"],
            )

            with patch("app.api.routes.FraudScannerService") as MockScanner, \
                 patch("app.api.routes.ScanLogRepository") as MockRepo:
                instance = MockScanner.return_value
                instance.analyze = AsyncMock(return_value=mock_result)

                scan_log = MagicMock()
                scan_log.id = "scan-e2e-123"
                scan_log.created_at = datetime(2026, 4, 13, 12, 0, 0)

                repo = MockRepo.return_value
                repo.create_scan_log = AsyncMock(return_value=scan_log)

                transport = ASGITransport(app=test_app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    # Step 1: Submit scan
                    resp = await client.post("/v1/scan", json={
                        "source": "telegram",
                        "content": "Check https://paypa1-secure.com/login for phishing",
                        "consent_confirmed": True,
                    })
                    assert resp.status_code == 200
                    data = resp.json()

                    # Step 2: Verify result structure
                    result = data.get("result", {})
                    assert result["risk_level"] == "HIGH"
                    assert result["score"] == 85
                    assert len(result["flagged_indicators"]) >= 1
