"""Type 8 — Load Tests: concurrent requests, throughput, and heavy traffic."""

import asyncio
import importlib
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ===================================================================
# Concurrent scanner safe_result generation
# ===================================================================

class TestScannerConcurrency:
    @pytest.fixture()
    def scanner_mod(self):
        return importlib.import_module("services.scanner")

    async def test_100_safe_results_concurrent(self, scanner_mod):
        svc = scanner_mod.AsyncScannerService()

        async def gen_safe(scan_type):
            return svc._safe_result(scan_type)

        tasks = [gen_safe(t) for t in ["phone", "url", "file", "image", "voice"] * 20]
        results = await asyncio.gather(*tasks)
        assert len(results) == 100
        assert all(r["risk_level"] == "LOW" for r in results)

    async def test_safe_result_throughput(self, scanner_mod):
        svc = scanner_mod.AsyncScannerService()
        start = time.perf_counter()
        for _ in range(1000):
            svc._safe_result("phone")
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, f"1000 safe_result calls took {elapsed:.2f}s (expected <2s)"


# ===================================================================
# Concurrent URL extraction
# ===================================================================

class TestUrlExtractionLoad:
    @pytest.fixture()
    def url_mod(self):
        return importlib.import_module("handlers.url")

    async def test_concurrent_url_extraction(self, url_mod):
        texts = [
            f"Visit https://evil{i}.com/login and http://phish{i}.org/steal"
            for i in range(50)
        ]

        async def extract(text):
            return url_mod.extract_urls(text)

        results = await asyncio.gather(*[extract(t) for t in texts])
        assert len(results) == 50
        assert all(len(urls) >= 2 for urls in results)

    def test_url_extraction_throughput(self, url_mod):
        text = "Check https://evil.com and http://phish.org/login and www.scam.net/verify"
        start = time.perf_counter()
        for _ in range(1000):
            url_mod.extract_urls(text)
        elapsed = time.perf_counter() - start
        assert elapsed < 3.0, f"1000 URL extractions took {elapsed:.2f}s"


# ===================================================================
# Concurrent phone validation
# ===================================================================

class TestPhoneValidationLoad:
    @pytest.fixture()
    def phone_mod(self):
        return importlib.import_module("handlers.phone")

    def test_phone_validation_throughput(self, phone_mod):
        numbers = ["+447700900123", "+919876543210", "+79991234567", "9876543210", "+4915112345678"]
        start = time.perf_counter()
        for _ in range(200):
            for num in numbers:
                phone_mod._validate_phone(num)
        elapsed = time.perf_counter() - start
        assert elapsed < 5.0, f"1000 phone validations took {elapsed:.2f}s"


# ===================================================================
# Concurrent keyword detection
# ===================================================================

class TestKeywordDetectionLoad:
    @pytest.fixture()
    def mod(self):
        return importlib.import_module("middleware.moderation")

    async def test_concurrent_banned_keyword_checks(self, mod):
        texts = [
            "I want to hack",
            "Check this email for phishing",
            "Deploy a botnet attack",
            "Is this number a scam?",
            "Credential stuffing tool",
        ] * 100

        async def check(text):
            return mod.find_banned_keywords(text)

        results = await asyncio.gather(*[check(t) for t in texts])
        assert len(results) == 500

    def test_keyword_search_throughput(self, mod):
        text = "This message contains no banned keywords and is completely safe for cybersecurity use"
        start = time.perf_counter()
        for _ in range(5000):
            mod.find_banned_keywords(text)
        elapsed = time.perf_counter() - start
        assert elapsed < 3.0, f"5000 keyword checks took {elapsed:.2f}s"


# ===================================================================
# Concurrent social database checks
# ===================================================================

class TestSocialDbChecksLoad:
    @pytest.fixture()
    def social_mod(self):
        return importlib.import_module("handlers.social")

    async def test_concurrent_database_checks(self, social_mod):
        async def check(i):
            return social_mod._database_checks(
                f"From @support_refund_team_{i} at t.me/scam{i}",
                [f"support_refund_team_{i}"],
                ["t.me"],
            )

        results = await asyncio.gather(*[check(i) for i in range(100)])
        assert len(results) == 100
        # Every result should at least detect the high-risk domain t.me
        assert all(len(hits) >= 1 for hits in results)


# ===================================================================
# Concurrent voice scam pattern detection
# ===================================================================

class TestVoicePatternDetectionLoad:
    @pytest.fixture()
    def voice_mod(self):
        return importlib.import_module("handlers.voice")

    async def test_concurrent_scam_detection(self, voice_mod):
        transcripts = [
            "Your aadhaar blocked please send otp now",
            "This is hmrc tax refund please provide bank details",
            "Hello I am calling about your amazon account suspended",
            "Normal conversation no scam here",
        ] * 25

        async def detect(transcript):
            return voice_mod._detect_scam_patterns(transcript)

        results = await asyncio.gather(*[detect(t) for t in transcripts])
        assert len(results) == 100

    def test_scam_detection_throughput(self, voice_mod):
        transcript = "Your aadhaar blocked and kyc update required please send otp immediately"
        start = time.perf_counter()
        for _ in range(2000):
            voice_mod._detect_scam_patterns(transcript)
        elapsed = time.perf_counter() - start
        assert elapsed < 3.0, f"2000 detections took {elapsed:.2f}s"


# ===================================================================
# Formatter throughput
# ===================================================================

class TestFormatterLoad:
    @pytest.fixture()
    def formatter(self):
        return importlib.import_module("services.formatter")

    def test_format_phone_throughput(self, formatter):
        data = {
            "scan_type": "phone",
            "risk_level": "HIGH",
            "score": 85,
            "summary": "Suspicious phone number detected.",
            "flags": ["Breach data", "Invalid carrier"],
            "details": {"country": "India", "carrier": "Unknown"},
        }
        start = time.perf_counter()
        for _ in range(1000):
            formatter.format_phone(data)
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0

    def test_risk_emoji_throughput(self, formatter):
        start = time.perf_counter()
        for _ in range(10000):
            formatter.risk_emoji("high")
            formatter.risk_emoji("medium")
            formatter.risk_emoji("low")
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0


# ===================================================================
# Database model creation throughput
# ===================================================================

class TestDatabaseLoad:
    async def test_concurrent_user_creation(self):
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
        db_mod = importlib.import_module("database.models")

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(db_mod.Base.metadata.create_all)

        factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

        async def create_user(idx):
            async with factory() as session:
                user = db_mod.User(
                    telegram_id=str(idx),
                    username=f"user_{idx}",
                    full_name=f"User {idx}",
                )
                session.add(user)
                await session.commit()

        # Create 50 users concurrently
        await asyncio.gather(*[create_user(i) for i in range(50)])

        async with factory() as session:
            result = await session.execute(
                db_mod.User.__table__.select()
            )
            rows = result.fetchall()
            assert len(rows) == 50

        await engine.dispose()


# ===================================================================
# FastAPI endpoint load (mocked)
# ===================================================================

class TestApiEndpointLoad:
    async def test_concurrent_scan_requests(self):
        from datetime import datetime
        from httpx import AsyncClient, ASGITransport
        from unittest.mock import patch
        from app.schemas import ScanResult

        # Lazy import to avoid engine creation
        with patch("app.db.database.engine"):
            from app.api.routes import router
            from fastapi import FastAPI

            test_app = FastAPI()
            test_app.include_router(router)

            mock_result = ScanResult(
                risk_level="LOW",
                score=10,
                summary="Safe content",
                explanation="No risk detected.",
                flagged_indicators=[],
                recommended_actions=[],
            )

            with patch("app.api.routes.FraudScannerService") as MockScanner, \
                 patch("app.api.routes.ScanLogRepository") as MockRepo:
                instance = MockScanner.return_value
                instance.analyze = AsyncMock(return_value=mock_result)

                def build_scan_log(index: int):
                    scan_log = MagicMock()
                    scan_log.id = f"scan-load-{index}"
                    scan_log.created_at = datetime(2026, 4, 13, 12, 0, 0)
                    return scan_log

                repo = MockRepo.return_value
                repo.create_scan_log = AsyncMock(side_effect=[build_scan_log(i) for i in range(20)])

                transport = ASGITransport(app=test_app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    tasks = []
                    for i in range(20):
                        tasks.append(
                            client.post(
                                "/v1/scan",
                                json={
                                    "source": "telegram",
                                    "content": f"Check this content {i}" + " padding" * 5,
                                    "consent_confirmed": True,
                                },
                            )
                        )
                    responses = await asyncio.gather(*tasks)
                    assert all(r.status_code == 200 for r in responses)
                    assert len(responses) == 20
