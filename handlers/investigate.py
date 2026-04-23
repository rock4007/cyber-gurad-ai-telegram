"""Investigation handler — /investigate command.

Usage:
  /investigate +919876543210
  /investigate John Doe +919876543210
  /investigate +919876543210 John Doe

The handler accepts a free-form argument string, extracts the phone number (if
present) and the remainder as the full name, runs the cross-database
investigation service, and returns a rich report to the investigator.
"""

from __future__ import annotations

import re

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatAction, ParseMode
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from middleware.quota import check_quota
from services.cross_db_investigation import CrossDatabaseInvestigator

_investigator = CrossDatabaseInvestigator()

# Matches E.164 or 10-digit local numbers
_PHONE_RE = re.compile(r"(\+?\d[\d\s\-()]{6,20}\d)")
_IP_RE = re.compile(r"\b(?:(?:\d{1,3})\.){3}(?:\d{1,3})\b")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_TWITTER_RE = re.compile(r"(?:x\.com|twitter\.com)/([A-Za-z0-9_\.]{1,32})", re.IGNORECASE)
_TG_RE = re.compile(r"(?:t\.me|telegram\.me)/([A-Za-z0-9_\.]{3,64})", re.IGNORECASE)


def _is_valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _normalize_mac(value: str) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(cleaned) != 12:
        return ""
    parts = [cleaned[i : i + 2] for i in range(0, 12, 2)]
    return ":".join(part.upper() for part in parts)


def _parse_args(raw: str) -> tuple[str, str]:
    """Return (full_name, phone) extracted from raw argument string."""
    raw = raw.strip()
    phone = ""
    name = raw

    match = _PHONE_RE.search(raw)
    if match:
        phone = re.sub(r"[^\d+]", "", match.group(0))
        name = raw[: match.start()].strip() + " " + raw[match.end() :].strip()
        name = name.strip()

    return name, phone


def _parse_investigation_request(raw: str) -> dict[str, object]:
    """Parse tier + name + phone + social IDs from free-form input."""
    text = raw.strip()
    lowered = text.lower()
    consent_confirmed = False
    privacy_mode = False

    consent_patterns = [
        r"\bconsent\s*[:=]\s*(yes|true|1)\b",
        r"\bi[_\s-]?consent\b",
        r"\bconsent\s+yes\b",
    ]
    for pattern in consent_patterns:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            consent_confirmed = True
            text = re.sub(pattern, "", text, flags=re.IGNORECASE).strip()
            lowered = text.lower()

    privacy_on_patterns = [
        r"\bprivacy\s*[:=]\s*(on|true|1)\b",
        r"\bprivate\s*[:=]\s*(on|true|1)\b",
    ]
    for pattern in privacy_on_patterns:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            privacy_mode = True
            text = re.sub(pattern, "", text, flags=re.IGNORECASE).strip()
            lowered = text.lower()

    privacy_off_patterns = [
        r"\bprivacy\s*[:=]\s*(off|false|0)\b",
        r"\bprivate\s*[:=]\s*(off|false|0)\b",
    ]
    for pattern in privacy_off_patterns:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            privacy_mode = False
            text = re.sub(pattern, "", text, flags=re.IGNORECASE).strip()
            lowered = text.lower()

    tier = "basic"
    for candidate in ("master", "pro", "basic"):
        if lowered.startswith(candidate + " ") or lowered == candidate:
            tier = candidate
            text = text[len(candidate):].strip()
            lowered = text.lower()
            break

    for candidate in ("tier:master", "tier:pro", "tier:basic"):
        if candidate in lowered:
            tier = candidate.split(":", 1)[1]
            text = re.sub(re.escape(candidate), "", text, flags=re.IGNORECASE).strip()
            lowered = text.lower()

    full_name, phone = _parse_args(text)
    ip_address = ""
    mac_address = ""
    email_address = ""
    telegram_id = ""
    telegram_group = ""
    twitter_id = ""

    ip_match = _IP_RE.search(text)
    if ip_match:
        candidate_ip = ip_match.group(0)
        if _is_valid_ipv4(candidate_ip):
            ip_address = candidate_ip
            text = (text[: ip_match.start()] + " " + text[ip_match.end() :]).strip()
            full_name, phone = _parse_args(text)

    ip_prefixed = re.search(r"\bip\s*[:=]\s*((?:\d{1,3}\.){3}\d{1,3})\b", text, flags=re.IGNORECASE)
    if ip_prefixed:
        candidate_ip = ip_prefixed.group(1)
        if _is_valid_ipv4(candidate_ip):
            ip_address = candidate_ip
            text = re.sub(r"\bip\s*[:=]\s*((?:\d{1,3}\.){3}\d{1,3})\b", "", text, flags=re.IGNORECASE).strip()
            full_name, phone = _parse_args(text)

    mac_match = _MAC_RE.search(text)
    if mac_match:
        normalized = _normalize_mac(mac_match.group(0))
        if normalized:
            mac_address = normalized
            text = (text[: mac_match.start()] + " " + text[mac_match.end() :]).strip()
            full_name, phone = _parse_args(text)

    mac_prefixed = re.search(r"\bmac\s*[:=]\s*([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b", text, flags=re.IGNORECASE)
    if mac_prefixed:
        normalized = _normalize_mac(mac_prefixed.group(1))
        if normalized:
            mac_address = normalized
            text = re.sub(r"\bmac\s*[:=]\s*([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b", "", text, flags=re.IGNORECASE).strip()
            full_name, phone = _parse_args(text)

    email_match = _EMAIL_RE.search(text)
    if email_match:
        email_address = email_match.group(0).strip().lower()
        text = (text[: email_match.start()] + " " + text[email_match.end() :]).strip()
        full_name, phone = _parse_args(text)

    email_prefixed = re.search(r"\bemail\s*[:=]\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", text, flags=re.IGNORECASE)
    if email_prefixed:
        email_address = email_prefixed.group(1).strip().lower()
        text = re.sub(r"\bemail\s*[:=]\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", "", text, flags=re.IGNORECASE).strip()
        full_name, phone = _parse_args(text)

    tw_match = _TWITTER_RE.search(text)
    if tw_match:
        twitter_id = tw_match.group(1)

    tg_matches = _TG_RE.findall(text)
    if tg_matches:
        telegram_id = tg_matches[0]
        if len(tg_matches) > 1:
            telegram_group = tg_matches[1]

    prefixed = re.findall(r"(tg|telegram|group|twitter|x):\s*(@?[A-Za-z0-9_\.]{2,64})", text, flags=re.IGNORECASE)
    for kind, handle in prefixed:
        cleaned = handle.lstrip("@")
        kind_l = kind.lower()
        if kind_l in {"tg", "telegram"}:
            telegram_id = cleaned
        elif kind_l == "group":
            telegram_group = cleaned
        elif kind_l in {"twitter", "x"}:
            twitter_id = cleaned

    return {
        "tier": tier,
        "consent_confirmed": consent_confirmed,
        "privacy_mode": privacy_mode,
        "full_name": full_name,
        "phone": phone,
        "email_address": email_address,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "telegram_id": telegram_id,
        "telegram_group": telegram_group,
        "twitter_id": twitter_id,
    }


def _risk_emoji(level: str) -> str:
    m = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "⚫"}
    return m.get(level.upper(), "⚪")


def _bar(score: int, length: int = 10) -> str:
    filled = max(0, min(length, round(score / 10)))
    return "█" * filled + "░" * (length - filled)


def _build_report(report: dict) -> str:
    query = report.get("query") or {}
    artifacts = report.get("artifact_id", "?")
    risk = str(report.get("risk_level", "UNKNOWN")).upper()
    score = int(report.get("score", 0))
    flags = report.get("flags") or []
    evidence = report.get("evidence") or []
    sources = report.get("sources_with_data") or []
    elapsed = report.get("elapsed_ms", 0)

    lines: list[str] = [
        "🔍 Investigation Report",
        "─────────────────────────",
        f"🆔 Artifact ID: {artifacts}",
        f"🧭 Plan Tier: {str(query.get('tier') or 'basic').upper()}",
    ]

    # query summary
    if query.get("full_name"):
        lines.append(f"👤 Name: {query['full_name']}")
    lines.append(f"✅ Consent: {'YES' if query.get('consent_confirmed') else 'NO'}")
    lines.append(f"🔐 Privacy Mode: {'ON' if query.get('privacy_mode', False) else 'OFF'}")
    if query.get("masked_probable_holder_name"):
        lines.append(f"🧑 Masked Holder: {query['masked_probable_holder_name']}")
    if query.get("probable_gender"):
        lines.append(f"⚧️ Gender Hint: {str(query['probable_gender']).upper()}")
    if query.get("activity_regions"):
        lines.append(f"📌 Activity Regions: {', '.join(query['activity_regions'][:5])}")
    if query.get("probable_holder_name") and not query.get("masked_probable_holder_name"):
        lines.append(f"🧑 Probable Holder: {query['probable_holder_name']}")
    if query.get("alternate_names"):
        lines.append(f"🪪 Alternate Names: {', '.join(query['alternate_names'][:4])}")
    if query.get("probable_social_handles"):
        handles = [f"@{h}" for h in query["probable_social_handles"][:6]]
        lines.append(f"🌐 Social Handles: {', '.join(handles)}")
    if query.get("identity_confidence"):
        lines.append(f"📈 Identity Confidence: {str(query['identity_confidence']).upper()}")
    if query.get("phone"):
        lines.append(f"📞 Number (masked): {query['phone']}")
    if query.get("email_address"):
        lines.append(f"✉️ Email: {query['email_address']}")
    if query.get("email_breach_count") is not None:
        lines.append(f"🔓 Email Breaches (HIBP): {query['email_breach_count']}")
    if query.get("ip_address"):
        lines.append(f"🌐 IP: {query['ip_address']}")
    if query.get("ip_city") or query.get("ip_country"):
        city = str(query.get("ip_city") or "").strip()
        country = str(query.get("ip_country") or "").strip()
        parts = [p for p in [city, country] if p]
        if parts:
            lines.append(f"📍 IP Geo: {', '.join(parts)}")
    if query.get("ip_isp"):
        lines.append(f"🏢 IP ISP: {query['ip_isp']}")
    if query.get("ip_vpn_or_proxy") is True:
        lines.append("🛡️ IP Network: VPN/Proxy or hosting detected")
    if query.get("mac_address"):
        lines.append(f"🧷 MAC: {query['mac_address']}")
    if query.get("mac_vendor"):
        lines.append(f"🏭 MAC Vendor: {query['mac_vendor']}")
    if query.get("phone_geo_area"):
        lines.append(f"🌍 Geo Area: {query['phone_geo_area']}")
    if query.get("phone_country"):
        lines.append(f"🗺️ Country: {query['phone_country']}")
    if query.get("phone_carrier"):
        lines.append(f"📡 Carrier: {query['phone_carrier']}")
    if query.get("phone_line_type"):
        lines.append(f"📶 Line Type: {query['phone_line_type']}")
    if query.get("network_geo_hint"):
        lines.append(f"🛰️ Network Geo Hint: {query['network_geo_hint']}")
    if query.get("associated_breach_emails"):
        emails = ", ".join(query["associated_breach_emails"][:5])
        lines.append(f"📧 Associated Breach Emails: {emails}")
    if query.get("tracking_status"):
        lines.append("🔒 Tracking: Disabled (defensive mode)")
    if query.get("telegram_id"):
        lines.append(f"📨 Telegram ID: @{query['telegram_id']}")
    if query.get("telegram_group"):
        lines.append(f"👥 Telegram Group: @{query['telegram_group']}")
    if query.get("twitter_id"):
        lines.append(f"🐦 X/Twitter ID: @{query['twitter_id']}")

    lines += [
        "─────────────────────────",
        f"⚠️ Risk: {_risk_emoji(risk)} {risk} ({score}/100)",
        _bar(score),
        "─────────────────────────",
    ]

    # flags
    if flags:
        lines.append("🚩 Intelligence Flags:")
        for f in flags[:8]:
            lines.append(f"  • {f}")
    else:
        lines.append("✅ No breach or scam indicators detected")

    lines.append("─────────────────────────")

    # sources with data summary
    breach_sources = [s for s in sources if s in {"haveibeenpwned", "leakcheck", "dehashed_phone",
                                                    "dehashed_name", "name_phone_cross_match"}]
    geo_sources = [s for s in sources if "geo" in s or "abstract" in s or "numverify" in s]
    scam_sources = [s for s in sources if "scam" in s]
    social_sources = [s for s in sources if "social" in s or s.startswith("dehashed_username_")]

    if breach_sources:
        lines.append(f"💾 Breach databases with data: {', '.join(breach_sources)}")
    if geo_sources:
        lines.append(f"📍 Carrier/geo sources: {', '.join(geo_sources)}")
    if scam_sources:
        lines.append(f"🕵️ Scam correlation: {', '.join(scam_sources)}")
    if social_sources:
        lines.append(f"🌐 Social checks: {', '.join(social_sources)}")

    # evidence highlights
    for ev in evidence:
        src = ev.get("source", "")
        d = ev.get("data") or {}
        conf = ev.get("confidence", "")

        if src == "dehashed_phone" and d.get("total", 0) > 0:
            lines.append("─────────────────────────")
            lines.append(f"📂 DeHashed (phone) — {d['total']} record(s) found:")
            for hit in (d.get("hits") or [])[:3]:
                db = hit.get("database_name") or "?"
                uname = hit.get("username") or hit.get("email") or "?"
                lines.append(f"  • DB: {db} | Identity hint: {uname}")

        if src == "dehashed_name" and d.get("total", 0) > 0:
            lines.append("─────────────────────────")
            lines.append(f"📂 DeHashed (name) — {d['total']} record(s) found:")
            for hit in (d.get("hits") or [])[:3]:
                db = hit.get("database_name") or "?"
                phone_h = hit.get("phone") or "?"
                lines.append(f"  • DB: {db} | Phone in record: {phone_h}")

        if src == "name_phone_cross_match":
            if d.get("matched"):
                lines.append("─────────────────────────")
                lines.append(f"⚡ Name + phone CROSS-MATCH confirmed in {d.get('match_count', 0)} breach record(s)")

        if src == "haveibeenpwned" and d.get("breach_count", 0) > 0:
            lines.append("─────────────────────────")
            lines.append(f"🔓 HaveIBeenPwned — {d['breach_count']} breach(es):")
            for b in (d.get("breach_names") or [])[:5]:
                lines.append(f"  • {b}")

        if src == "leakcheck" and d.get("found"):
            lines.append("─────────────────────────")
            lines.append(f"🔓 LeakCheck — found in {d.get('source_count', 0)} source(s):")
            for s in (d.get("sources") or [])[:5]:
                lines.append(f"  • {s}")

        if src == "abstract_phone_api" and d.get("is_voip"):
            lines.append("─────────────────────────")
            lines.append("⚠️ VoIP number detected (AbstractAPI) — high fraud risk")
            if d.get("carrier"):
                lines.append(f"  Carrier: {d['carrier']}")

        if src == "scam_report_correlation" and d.get("flagged"):
            lines.append("─────────────────────────")
            for sf in d.get("scam_flags") or []:
                lines.append(f"🚨 {sf}")

        if src == "social_identity_checks":
            checks = d.get("checks") or {}
            if checks:
                lines.append("─────────────────────────")
                lines.append("🌐 Social Identity Checks:")
                for k, v in checks.items():
                    verdict = v.get("verdict", "inconclusive")
                    status_code = v.get("status_code")
                    lines.append(f"  • {k}: {verdict} (status={status_code})")
            for hit in d.get("suspicious_hits") or []:
                lines.append(f"  • ⚠️ {hit}")

    lines += [
        "─────────────────────────",
        f"⏱️ Completed in {elapsed}ms",
        f"📅 {report.get('generated_at', '')}",
        "─────────────────────────",
        "🎓 Educational & defensive use only.",
        "⛔ Illegal or abusive requests are blocked.",
        "⚠️ Evidence shown is from public breach & reputation sources only.",
        "Use findings as investigative leads — verify before acting.",
    ]

    return "\n".join(lines)


def _buttons(artifact_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📋 Full Evidence", callback_data=f"inv_evidence:{artifact_id}"),
            InlineKeyboardButton("📤 Export JSON", callback_data=f"inv_export:{artifact_id}"),
        ],
        [InlineKeyboardButton("🔍 New Investigation", callback_data="inv_new")],
    ])


@check_quota
async def investigate_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return

    raw = " ".join(context.args).strip() if context.args else ""
    if not raw:
        await update.message.reply_text(
            "🔍 Investigation Command\n"
            "─────────────────────────\n"
            "Usage:\n"
            "  /investigate <phone>\n"
            "  /investigate <ip>\n"
            "  /investigate <mac>\n"
            "  /investigate <email>\n"
            "  /investigate <full name> <phone>\n"
            "  /investigate <tier> <full name/phone/email/ip/mac/social ids>\n"
            "  tiers: basic | pro | master\n\n"
            "For identity enrichment fields, include consent token:\n"
            "  consent:yes or i_consent\n\n"
            "Privacy mode is OFF by default (real output).\n"
            "  optional: privacy:on\n\n"
            "Unmasked IP/MAC/social output is available for pro/master only.\n\n"
            "Examples:\n"
            "  /investigate +919876543210\n"
            "  /investigate 8.8.8.8\n"
            "  /investigate 00:1A:2B:3C:4D:5E\n"
            "  /investigate email:test@example.com\n"
            "  /investigate John Doe +919876543210\n\n"
            "  /investigate pro consent:yes tg:sample_user twitter:samplex\n"
            "  /investigate master consent:yes John Doe +919876543210 group:my_group\n"
            "  /investigate pro ip:1.1.1.1 mac:00-1A-2B-3C-4D-5E\n\n"
            "Searches public breach databases, phone intelligence, "
            "scam reports, and geolocation sources.\n"
            "All results are from public/breach-intel APIs only.\n"
            "Educational/defensive use only; illegal requests are blocked."
        )
        return

    parsed = _parse_investigation_request(raw)
    full_name = parsed["full_name"]
    phone = parsed["phone"]
    email_address = parsed["email_address"]
    ip_address = parsed["ip_address"]
    mac_address = parsed["mac_address"]
    telegram_id = parsed["telegram_id"]
    telegram_group = parsed["telegram_group"]
    twitter_id = parsed["twitter_id"]
    tier = parsed["tier"]
    consent_confirmed = bool(parsed.get("consent_confirmed"))
    privacy_mode = bool(parsed.get("privacy_mode", False))

    if not phone and not email_address and not ip_address and not mac_address and not full_name and not telegram_id and not telegram_group and not twitter_id:
        await update.message.reply_text("Please provide at least one identity: phone, email, IP, MAC, name, Telegram ID/group, or Twitter ID.")
        return

    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id, action=ChatAction.TYPING
    )
    await update.message.reply_text("🔍 Running cross-database investigation…")

    try:
        report = await _investigator.investigate(
            full_name=full_name,
            phone=phone,
            email_address=email_address,
            ip_address=ip_address,
            mac_address=mac_address,
            telegram_id=telegram_id,
            telegram_group=telegram_group,
            twitter_id=twitter_id,
            tier=tier,
            consent_confirmed=consent_confirmed,
            privacy_mode=privacy_mode,
        )
    except Exception as exc:
        await update.message.reply_text(f"Investigation failed: {exc}")
        return

    # store in user_data for evidence/export callbacks
    artifact_id = report.get("artifact_id", "?")
    context.user_data[f"inv:{artifact_id}"] = report

    text = _build_report(report)

    # Telegram message limit
    if len(text) > 4000:
        text = text[:3997] + "…"

    await update.message.reply_text(
        text,
        reply_markup=_buttons(artifact_id),
    )


async def _inv_evidence_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return
    await update.callback_query.answer()
    artifact_id = (update.callback_query.data or "").split(":", 1)[-1]
    report = context.user_data.get(f"inv:{artifact_id}")
    if not report:
        await update.callback_query.message.reply_text("Report expired. Run /investigate again.")
        return

    evidence = report.get("evidence") or []
    if not evidence:
        await update.callback_query.message.reply_text("No evidence records found.")
        return

    lines = ["📋 Full Evidence Records", "─────────────────────────"]
    for ev in evidence:
        lines.append(f"\n[{ev['source'].upper()}] confidence={ev['confidence']}")
        lines.append(f"fetched: {ev['fetched_at']}")
        d = ev.get("data") or {}
        for k, v in d.items():
            if v is not None and v != "" and v != [] and v != {}:
                lines.append(f"  {k}: {v}")

    text = "\n".join(lines)
    if len(text) > 4000:
        text = text[:3997] + "…"
    await update.callback_query.message.reply_text(text)


async def _inv_export_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    import json

    if not update.callback_query:
        return
    await update.callback_query.answer()
    artifact_id = (update.callback_query.data or "").split(":", 1)[-1]
    report = context.user_data.get(f"inv:{artifact_id}")
    if not report:
        await update.callback_query.message.reply_text("Report expired. Run /investigate again.")
        return

    text = json.dumps(report, indent=2, default=str)
    if len(text) > 4000:
        text = text[:3997] + "…\n(truncated — too large for Telegram)"
    await update.callback_query.message.reply_text(f"```json\n{text}\n```", parse_mode=ParseMode.MARKDOWN)


async def _inv_new_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return
    await update.callback_query.answer()
    await update.callback_query.message.reply_text(
        "Send /investigate <phone>, <email>, <ip>, <mac>, or /investigate <name> <phone> to start a new investigation."
    )


def register_investigate_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("investigate", investigate_command))
    application.add_handler(CallbackQueryHandler(_inv_evidence_callback, pattern=r"^inv_evidence:"))
    application.add_handler(CallbackQueryHandler(_inv_export_callback, pattern=r"^inv_export:"))
    application.add_handler(CallbackQueryHandler(_inv_new_callback, pattern=r"^inv_new$"))
