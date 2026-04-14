def test_progress_bar_respects_length(formatter):
    bar = formatter.progress_bar(50, total=100, length=10)
    assert len(bar) == 10
    assert bar.count("█") == 5


def test_risk_emoji_levels(formatter):
    assert formatter.risk_emoji("LOW") == "🟢"
    assert formatter.risk_emoji("MEDIUM") == "🟡"
    assert formatter.risk_emoji("HIGH") == "🔴"


def test_format_url_contains_header(formatter):
    payload = {
        "scan_type": "url",
        "risk_level": "LOW",
        "score": 10,
        "summary": "Looks clean",
        "flags": [],
    }
    message = formatter.format_url(payload)
    assert "CyberGuard URL Scan" in message
    assert "Risk:" in message
