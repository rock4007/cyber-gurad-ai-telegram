TELEGRAM_LIMIT = 4096
DIVIDER = "─────────────────"


def _escape_md_v2(text: str) -> str:
    # Telegram MarkdownV2 reserved characters.
    chars = r"_*[]()~`>#+-=|{}.!"
    escaped = []
    for ch in text:
        if ch in chars:
            escaped.append("\\" + ch)
        else:
            escaped.append(ch)
    return "".join(escaped)


def _clip(text: str, max_chars: int = TELEGRAM_LIMIT) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1] + "…"


def _result_obj(data: dict) -> dict:
    if isinstance(data.get("result"), dict):
        return data["result"]
    return data


def _risk_level(data: dict) -> str:
    return str(_result_obj(data).get("risk_level", "LOW")).upper()


def _score(data: dict) -> int:
    try:
        return max(0, min(100, int(_result_obj(data).get("score", 0) or 0)))
    except (TypeError, ValueError):
        return 0


def _summary(data: dict) -> str:
    result = _result_obj(data)
    text = str(result.get("summary", "No summary available.")).strip()
    if text:
        return text
    return "No summary available."


def _top_finding(data: dict) -> str:
    result = _result_obj(data)
    flags = result.get("flagged_indicators") or result.get("flags") or []
    if isinstance(flags, list) and flags:
        return str(flags[0])

    explanation = str(result.get("explanation", "")).strip()
    if explanation:
        return explanation.splitlines()[0][:160]

    return "No strong indicator detected."


def _advice(data: dict, default: str) -> str:
    result = _result_obj(data)
    actions = result.get("recommended_actions") or []
    if isinstance(actions, list) and actions:
        return str(actions[0])
    return default


def _origin_lines(data: dict) -> list[str]:
    """Build location-intelligence lines if available in the result details."""
    result = _result_obj(data)
    details = result.get("details") or {}
    origin = details.get("origin_intelligence") or {}
    best = origin.get("best_estimate") or {}
    country = best.get("country")
    if not country or country == "Unknown":
        return []

    city = best.get("city") or "?"
    confidence = best.get("confidence", "?")
    vpn = best.get("vpn_detected", False)

    lines = [
        DIVIDER,
        f"📍 Origin: {_escape_md_v2(city)}, {_escape_md_v2(country)} \\(confidence: {_escape_md_v2(confidence)}\\)",
    ]
    if vpn:
        lines.append("🛡️ VPN/Proxy detected — real hosting location resolved")
    return lines


def _build_scan_message(title: str, data: dict, advice_default: str) -> str:
    level = _risk_level(data)
    score = _score(data)
    summary = _summary(data)
    top = _top_finding(data)
    advice = _advice(data, advice_default)

    lines = [
        _escape_md_v2(title),
        DIVIDER,
        f"Risk: {risk_emoji(level)} {_escape_md_v2(level)} \({_escape_md_v2(str(score))}/100\)",
        f"Meter: {_escape_md_v2(progress_bar(score))}",
        DIVIDER,
        f"Top finding: {_escape_md_v2(top)}",
        f"Summary: {_escape_md_v2(summary)}",
        DIVIDER,
        f"Advice: {_escape_md_v2(advice)}",
    ]

    lines.extend(_origin_lines(data))

    return _clip("\n".join(lines))


def risk_emoji(level: str) -> str:
    normalized = str(level or "").upper()
    if normalized == "LOW":
        return "🟢"
    if normalized == "MEDIUM":
        return "🟡"
    if normalized == "HIGH":
        return "🔴"
    if normalized == "CRITICAL":
        return "⚫"
    return "⚪"


def progress_bar(
    score: int,
    total: int = 100,
    length: int = 10,
    *,
    max: int | None = None,
) -> str:
    # Preserve compatibility with callers that still pass max=...
    if max is not None:
        total = max

    if total <= 0:
        total = 100
    if length <= 0:
        length = 10

    safe_score = total if score > total else 0 if score < 0 else score
    filled = int((safe_score / total) * length)
    return "█" * filled + "░" * (length - filled)


def shorten_hash(hash: str) -> str:
    value = str(hash or "")
    if len(value) <= 16:
        return value
    return value[:8] + "..." + value[-8:]


def format_phone(data: dict) -> str:
    return _build_scan_message(
        "📞 CyberGuard Phone Scan",
        data,
        "Do not share OTP, PIN, or bank details with unknown callers.",
    )


def format_url(data: dict) -> str:
    return _build_scan_message(
        "🔗 CyberGuard URL Scan",
        data,
        "Avoid opening the link until domain and sender identity are verified.",
    )


def format_file(data: dict) -> str:
    base = _build_scan_message(
        "📁 CyberGuard File Scan",
        data,
        "Do not execute suspicious files; isolate and re-scan before opening.",
    )
    result = _result_obj(data)
    details = result.get("details", {}) if isinstance(result.get("details", {}), dict) else {}
    sha256 = str(details.get("sha256", "")).strip()
    if sha256:
        base += "\n" + DIVIDER + "\n" + f"SHA256: {_escape_md_v2(shorten_hash(sha256))}"
    return _clip(base)


def format_image(data: dict) -> str:
    return _build_scan_message(
        "🖼️ CyberGuard Image Scan",
        data,
        "Remove sensitive metadata before sharing images publicly.",
    )


def format_voice(data: dict) -> str:
    return _build_scan_message(
        "🎙️ CyberGuard Voice Scan",
        data,
        "Hang up and verify the caller using official channels.",
    )


def format_error(error: str) -> str:
    message = (
        "⚠️ CyberGuard Error\n"
        f"{DIVIDER}\n"
        "Risk: ⚪ UNKNOWN \(0/100\)\n"
        f"Top finding: {_escape_md_v2(str(error or 'Unexpected failure'))}\n"
        "Advice: Please retry in a moment or contact support if this repeats\."
    )
    return _clip(message)


def format_quota_exceeded(user: dict) -> str:
    plan = str(user.get("plan", "free")).lower()
    used = int(user.get("used", 0) or 0)
    limit = int(user.get("limit", 0) or 0)
    return _clip(
        "📉 Monthly Quota Reached\n"
        f"{DIVIDER}\n"
        "Risk: ⚪ INFO \(0/100\)\n"
        f"Top finding: You used {_escape_md_v2(str(used))}/{_escape_md_v2(str(limit))} scans on {_escape_md_v2(plan)} plan\.\n"
        "Advice: Upgrade your plan to continue scanning this month\."
    )


def format_ban_notice(reason: str) -> str:
    return _clip(
        "⛔ Access Restricted\n"
        f"{DIVIDER}\n"
        "Risk: ⚫ CRITICAL \(100/100\)\n"
        f"Top finding: {_escape_md_v2(reason or 'Policy violation')}\n"
        "Advice: Contact support if you believe this is a mistake\."
    )


def format_warning(strikes: int, reason: str) -> str:
    safe_strikes = 0 if strikes < 0 else strikes
    return _clip(
        "⚠️ Policy Warning\n"
        f"{DIVIDER}\n"
        f"Risk: 🟡 MEDIUM \({_escape_md_v2(str(min(99, safe_strikes * 30)))}/100\)\n"
        f"Top finding: {_escape_md_v2(reason or 'Suspicious behavior detected')}\n"
        f"Advice: Stop prohibited activity\. Current strikes: {_escape_md_v2(str(safe_strikes))}\."
    )


def format_status(user: dict) -> str:
    plan = str(user.get("plan", "free")).lower()
    used = int(user.get("used", 0) or 0)
    limit = int(user.get("limit", 0) or 0)
    remaining = max(0, limit - used)
    meter_score = 0 if limit <= 0 else int((used / limit) * 100)

    return _clip(
        "📊 CyberGuard Status\n"
        f"{DIVIDER}\n"
        f"Risk: ⚪ INFO \({_escape_md_v2(str(meter_score))}/100\)\n"
        f"Top finding: {_escape_md_v2(str(remaining))} scans remaining this month\.\n"
        f"Advice: Plan {_escape_md_v2(plan)} usage is {_escape_md_v2(str(used))}/{_escape_md_v2(str(limit))}\."
    )


def format_scan_result(scan_payload: dict) -> str:
    # Backward-compatible entry point used in main.py.
    result = _result_obj(scan_payload)
    scan_type = str(result.get("scan_type") or scan_payload.get("scan_type") or "").lower()

    if scan_type == "phone":
        return format_phone(scan_payload)
    if scan_type == "file":
        return format_file(scan_payload)
    if scan_type == "image":
        return format_image(scan_payload)
    if scan_type == "voice":
        return format_voice(scan_payload)
    return format_url(scan_payload)
