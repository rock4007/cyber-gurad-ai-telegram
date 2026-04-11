import json
import re


def _parse_ai_response(raw: str) -> dict:
    """Extract JSON from the AI response text."""
    try:
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            return json.loads(match.group())
    except (json.JSONDecodeError, AttributeError):
        pass
    return {"risk_level": "unknown", "summary": raw, "indicators": []}


def _risk_emoji(risk_level: str) -> str:
    return {
        "safe": "✅",
        "suspicious": "⚠️",
        "dangerous": "🚨",
    }.get(risk_level.lower(), "❓")


def format_url_report(result: dict) -> str:
    parsed = _parse_ai_response(result.get("raw_response", ""))
    risk = parsed.get("risk_level", "unknown")
    emoji = _risk_emoji(risk)
    lines = [
        f"{emoji} *URL Scan Result*",
        f"🔗 URL: `{result.get('url', 'N/A')}`",
        f"Risk level: *{risk.upper()}*",
        f"\n{parsed.get('summary', '')}",
    ]
    indicators = parsed.get("indicators", [])
    if indicators:
        lines.append("\n*Threat indicators:*")
        lines.extend(f"  • {ind}" for ind in indicators)
    return "\n".join(lines)


def format_phone_report(result: dict) -> str:
    parsed = _parse_ai_response(result.get("raw_response", ""))
    risk = parsed.get("risk_level", "unknown")
    emoji = _risk_emoji(risk)
    valid_label = "✅ Valid" if result.get("is_valid") else "❌ Invalid"
    lines = [
        f"{emoji} *Phone Number Scan Result*",
        f"📞 Number: `{result.get('phone_number', 'N/A')}`",
        f"Format: {valid_label}",
        f"Risk level: *{risk.upper()}*",
        f"\n{parsed.get('summary', '')}",
    ]
    indicators = parsed.get("indicators", [])
    if indicators:
        lines.append("\n*Threat indicators:*")
        lines.extend(f"  • {ind}" for ind in indicators)
    return "\n".join(lines)


def format_file_report(result: dict) -> str:
    parsed = _parse_ai_response(result.get("raw_response", ""))
    risk = parsed.get("risk_level", "unknown")
    emoji = _risk_emoji(risk)
    lines = [
        f"{emoji} *File Scan Result*",
        f"📄 File: `{result.get('file_name', 'N/A')}`",
        f"Type: `{result.get('mime_type', 'N/A')}`",
        f"SHA-256: `{result.get('sha256', 'N/A')}`",
        f"Risk level: *{risk.upper()}*",
        f"\n{parsed.get('summary', '')}",
    ]
    indicators = parsed.get("indicators", [])
    if indicators:
        lines.append("\n*Threat indicators:*")
        lines.extend(f"  • {ind}" for ind in indicators)
    return "\n".join(lines)


def format_voice_report(result: dict) -> str:
    parsed = _parse_ai_response(result.get("raw_response", ""))
    risk = parsed.get("risk_level", "unknown")
    emoji = _risk_emoji(risk)
    lines = [
        f"{emoji} *Voice Message Analysis*",
        f"⏱️ Duration: {result.get('duration', 0)}s",
        f"Risk level: *{risk.upper()}*",
        f"\n{parsed.get('summary', '')}",
    ]
    indicators = parsed.get("indicators", [])
    if indicators:
        lines.append("\n*Threat indicators:*")
        lines.extend(f"  • {ind}" for ind in indicators)
    return "\n".join(lines)


def format_image_report(result: dict) -> str:
    parsed = _parse_ai_response(result.get("raw_response", ""))
    risk = parsed.get("risk_level", "unknown")
    emoji = _risk_emoji(risk)
    lines = [
        f"{emoji} *Image Analysis*",
        f"Risk level: *{risk.upper()}*",
        f"\n{parsed.get('summary', '')}",
    ]
    indicators = parsed.get("indicators", [])
    if indicators:
        lines.append("\n*Threat indicators:*")
        lines.extend(f"  • {ind}" for ind in indicators)
    return "\n".join(lines)
