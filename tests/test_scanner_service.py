import asyncio
import importlib
import os
import sys
from pathlib import Path


# Required by cyberguard-telegram/config.py at import time.
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("BOT_TOKEN", "test-bot-token")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-anthropic-key")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ADMIN_IDS", "12345")
os.environ.setdefault("BACKEND_URL", "http://localhost:8000")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BOT_ROOT = PROJECT_ROOT / "cyberguard-telegram"
if str(BOT_ROOT) not in sys.path:
    sys.path.insert(0, str(BOT_ROOT))

scanner_mod = importlib.import_module("services.scanner")
AsyncScannerService = scanner_mod.AsyncScannerService


def _run(coro):
    return asyncio.run(coro)


def test_safe_result_structure() -> None:
    service = AsyncScannerService()
    result = service._safe_result("url")

    assert result["scan_type"] == "url"
    assert result["risk_level"] == "LOW"
    assert result["score"] == 0
    assert isinstance(result["flags"], list)
    assert isinstance(result["details"], dict)


def test_scan_phone_medium_for_invalid_and_abstract_flag(monkeypatch) -> None:
    service = AsyncScannerService()
    service.abstract_phone_key = "demo-key"

    monkeypatch.setattr(scanner_mod.phonenumbers, "is_valid_number", lambda _parsed: False)

    async def fake_get(*_args, **_kwargs):
        return {"valid": False}

    monkeypatch.setattr(service, "_http_get_json", fake_get)

    result = _run(service.scan_phone("+14155552671", "u-1"))

    assert result["scan_type"] == "phone"
    assert result["risk_level"] == "MEDIUM"
    assert result["score"] == 40
    assert "Invalid or malformed number" in result["flags"]
    assert "Abstract phone API marked number invalid" in result["flags"]


def test_scan_url_high_when_multiple_signals(monkeypatch) -> None:
    service = AsyncScannerService()
    service.google_safe_browsing_key = "gsb-key"

    async def fake_post(url, *args, **kwargs):
        if "threatMatches:find" in url:
            return {"matches": [{"threatType": "MALWARE"}]}
        return {"query_status": "ok"}

    async def fake_get(url, *args, **kwargs):
        if "rdap.org" in url:
            return {
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": "2026-04-01T00:00:00Z",
                    }
                ]
            }
        return None

    monkeypatch.setattr(service, "_http_post_json", fake_post)
    monkeypatch.setattr(service, "_http_get_json", fake_get)

    result = _run(service.scan_url("https://example-test-site.com/login", "u-2"))

    assert result["scan_type"] == "url"
    assert result["risk_level"] == "HIGH"
    assert result["score"] == 100
    assert "Google Safe Browsing flagged this URL" in result["flags"]
    assert "URLhaus lists this URL as malicious" in result["flags"]


def test_scan_file_returns_fallback_for_missing_file() -> None:
    service = AsyncScannerService()
    result = _run(service.scan_file("D:/telegram bot/tests/does-not-exist.bin", "u-3"))

    assert result["scan_type"] == "file"
    assert result["risk_level"] == "LOW"
    assert result["score"] == 0


def test_scan_file_uses_virustotal_signal(monkeypatch, tmp_path) -> None:
    service = AsyncScannerService()

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"test-binary")

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key")

    async def fake_get(*_args, **_kwargs):
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 8,
                        "suspicious": 5,
                    }
                }
            }
        }

    monkeypatch.setattr(service, "_http_get_json", fake_get)

    result = _run(service.scan_file(str(sample), "u-4"))

    assert result["scan_type"] == "file"
    assert result["risk_level"] == "MEDIUM"
    assert result["score"] >= 60
    assert any("VirusTotal" in flag for flag in result["flags"])


def test_generate_report_returns_fallback_on_exception(monkeypatch) -> None:
    service = AsyncScannerService()

    async def broken_create(*_args, **_kwargs):
        raise RuntimeError("upstream unavailable")

    monkeypatch.setattr(service._claude.messages, "create", broken_create)

    report = _run(service.generate_report({"scan_type": "url", "score": 80}))
    assert report == "Threat report is temporarily unavailable."
