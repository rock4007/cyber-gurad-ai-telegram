"""Tests for services/formatter.py — Telegram MarkdownV2 message formatting."""


# ── risk_emoji ──────────────────────────────────────────────────────────────

def test_risk_emoji_low(formatter):
    assert formatter.risk_emoji("LOW") == "🟢"


def test_risk_emoji_medium(formatter):
    assert formatter.risk_emoji("MEDIUM") == "🟡"


def test_risk_emoji_high(formatter):
    assert formatter.risk_emoji("HIGH") == "🔴"


def test_risk_emoji_critical(formatter):
    assert formatter.risk_emoji("CRITICAL") == "⚫"


def test_risk_emoji_unknown(formatter):
    assert formatter.risk_emoji("") == "⚪"


def test_risk_emoji_case_insensitive(formatter):
    assert formatter.risk_emoji("low") == "🟢"
    assert formatter.risk_emoji("High") == "🔴"


# ── progress_bar ────────────────────────────────────────────────────────────

def test_progress_bar_zero(formatter):
    bar = formatter.progress_bar(0)
    assert bar == "░" * 10


def test_progress_bar_full(formatter):
    bar = formatter.progress_bar(100)
    assert bar == "█" * 10


def test_progress_bar_half(formatter):
    bar = formatter.progress_bar(50)
    assert "█" in bar and "░" in bar
    assert bar.count("█") == 5


def test_progress_bar_negative_clamps(formatter):
    bar = formatter.progress_bar(-10)
    assert bar == "░" * 10


def test_progress_bar_over_max_clamps(formatter):
    bar = formatter.progress_bar(200)
    assert bar == "█" * 10


# ── shorten_hash ────────────────────────────────────────────────────────────

def test_shorten_hash_short(formatter):
    assert formatter.shorten_hash("abc") == "abc"


def test_shorten_hash_long(formatter):
    h = "a" * 64
    result = formatter.shorten_hash(h)
    assert len(result) == 19  # 8 + 3 + 8
    assert result.startswith("aaaaaaaa...")


def test_shorten_hash_empty(formatter):
    assert formatter.shorten_hash("") == ""


# ── format_phone ────────────────────────────────────────────────────────────

def test_format_phone_contains_title_and_risk(formatter):
    data = {
        "scan_type": "phone",
        "risk_level": "LOW",
        "score": 10,
        "summary": "Phone is safe.",
        "flags": ["No issues"],
        "details": {},
    }
    msg = formatter.format_phone(data)
    assert "CyberGuard Phone Scan" in msg
    assert "🟢" in msg


def test_format_phone_high_risk(formatter):
    data = {
        "scan_type": "phone",
        "risk_level": "HIGH",
        "score": 85,
        "summary": "Known scam number.",
        "flags": ["Breach found"],
        "details": {},
    }
    msg = formatter.format_phone(data)
    assert "🔴" in msg
    assert "HIGH" in msg


# ── format_url ──────────────────────────────────────────────────────────────

def test_format_url_contains_url_title(formatter):
    data = {"risk_level": "MEDIUM", "score": 55, "flags": ["New domain"], "summary": "Caution."}
    msg = formatter.format_url(data)
    assert "CyberGuard URL Scan" in msg
    assert "🟡" in msg


# ── format_file with sha256 ────────────────────────────────────────────────

def test_format_file_includes_sha256(formatter):
    sha = "a" * 64
    data = {
        "risk_level": "HIGH",
        "score": 90,
        "flags": ["Malware"],
        "summary": "Infected.",
        "details": {"sha256": sha},
    }
    msg = formatter.format_file(data)
    assert "SHA256" in msg
    assert "aaaaaaaa" in msg  # shortened hash prefix


def test_format_file_no_sha256(formatter):
    data = {"risk_level": "LOW", "score": 0, "flags": [], "summary": "Clean.", "details": {}}
    msg = formatter.format_file(data)
    assert "SHA256" not in msg


# ── format_image / format_voice ─────────────────────────────────────────────

def test_format_image_title(formatter):
    data = {"risk_level": "LOW", "score": 0, "flags": [], "summary": "No metadata."}
    assert "CyberGuard Image Scan" in formatter.format_image(data)


def test_format_voice_title(formatter):
    data = {"risk_level": "MEDIUM", "score": 45, "flags": ["Scam pattern"], "summary": "Be careful."}
    assert "CyberGuard Voice Scan" in formatter.format_voice(data)


# ── format_error ────────────────────────────────────────────────────────────

def test_format_error_includes_message(formatter):
    msg = formatter.format_error("Service unavailable")
    assert "Service unavailable" in msg
    assert "CyberGuard Error" in msg


def test_format_error_empty_string(formatter):
    msg = formatter.format_error("")
    assert "Unexpected failure" in msg


# ── format_quota_exceeded ───────────────────────────────────────────────────

def test_format_quota_exceeded(formatter):
    user = {"plan": "free", "used": 5, "limit": 5}
    msg = formatter.format_quota_exceeded(user)
    assert "Monthly Quota Reached" in msg
    assert "5" in msg


# ── format_ban_notice ───────────────────────────────────────────────────────

def test_format_ban_notice(formatter):
    msg = formatter.format_ban_notice("Spam abuse detected")
    assert "Access Restricted" in msg
    assert "Spam abuse detected" in msg


# ── format_warning ──────────────────────────────────────────────────────────

def test_format_warning(formatter):
    msg = formatter.format_warning(2, "Repeated offensive messages")
    assert "Policy Warning" in msg
    assert "2" in msg


# ── format_status ───────────────────────────────────────────────────────────

def test_format_status(formatter):
    user = {"plan": "pro", "used": 20, "limit": 500}
    msg = formatter.format_status(user)
    assert "CyberGuard Status" in msg
    assert "480" in msg  # 500 - 20


# ── format_scan_result dispatch ─────────────────────────────────────────────

def test_format_scan_result_dispatches_phone(formatter):
    data = {
        "scan_type": "phone",
        "risk_level": "LOW",
        "score": 0,
        "summary": "OK",
        "flags": [],
    }
    msg = formatter.format_scan_result(data)
    assert "Phone Scan" in msg


def test_format_scan_result_dispatches_url(formatter):
    data = {
        "scan_type": "url",
        "risk_level": "HIGH",
        "score": 80,
        "summary": "Bad link",
        "flags": ["Phish"],
    }
    msg = formatter.format_scan_result(data)
    assert "URL Scan" in msg


def test_format_scan_result_unknown_type_falls_to_url(formatter):
    data = {"scan_type": "other", "risk_level": "LOW", "score": 0, "flags": [], "summary": "OK"}
    msg = formatter.format_scan_result(data)
    assert "URL Scan" in msg


# ── origin intelligence in formatted output ─────────────────────────────────

def test_format_url_includes_origin_intelligence(formatter):
    data = {
        "risk_level": "HIGH",
        "score": 90,
        "flags": ["Phishing"],
        "summary": "Dangerous.",
        "details": {
            "origin_intelligence": {
                "best_estimate": {
                    "country": "Nigeria",
                    "city": "Lagos",
                    "confidence": "high",
                    "vpn_detected": True,
                },
            },
        },
    }
    msg = formatter.format_url(data)
    assert "Lagos" in msg
    assert "Nigeria" in msg
    assert "VPN" in msg


def test_format_url_no_origin_when_unknown(formatter):
    data = {
        "risk_level": "LOW",
        "score": 5,
        "flags": [],
        "summary": "Safe",
        "details": {
            "origin_intelligence": {
                "best_estimate": {"country": "Unknown"},
            },
        },
    }
    msg = formatter.format_url(data)
    assert "Origin" not in msg


# ── message length limit ───────────────────────────────────────────────────

def test_message_clipped_at_telegram_limit(formatter):
    data = {
        "risk_level": "HIGH",
        "score": 99,
        "flags": ["A" * 5000],
        "summary": "B" * 5000,
    }
    msg = formatter.format_phone(data)
    assert len(msg) <= formatter.TELEGRAM_LIMIT


# ── MarkdownV2 escaping ────────────────────────────────────────────────────

def test_escape_md_v2_escapes_special_chars(formatter):
    escaped = formatter._escape_md_v2("Hello_World [test] (ok)")
    assert "\\_" in escaped
    assert "\\[" in escaped
    assert "\\(" in escaped
