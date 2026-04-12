def format_scan_result(scan_payload: dict) -> str:
    result = scan_payload.get("result", {})
    risk_level = str(result.get("risk_level", "unknown")).upper()
    score = result.get("score", "n/a")
    summary = str(result.get("summary", "No summary provided.")).strip()
    explanation = str(result.get("explanation", "")).strip()

    actions = result.get("recommended_actions", [])
    indicators = result.get("flagged_indicators", [])

    lines = [
        "CyberGuard AI Analysis",
        "",
        f"Risk: {risk_level} ({score}/100)",
        f"Summary: {summary}",
    ]

    if explanation:
        lines.append("")
        lines.append("Explanation:")
        lines.append(explanation)

    if indicators:
        lines.append("")
        lines.append("Indicators:")
        lines.extend(f"- {item}" for item in indicators)

    if actions:
        lines.append("")
        lines.append("Recommended actions:")
        lines.extend(f"- {item}" for item in actions)

    return "\n".join(lines)
