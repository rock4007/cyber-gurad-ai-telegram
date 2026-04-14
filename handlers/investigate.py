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
    ]

    # query summary
    if query.get("full_name"):
        lines.append(f"👤 Name: {query['full_name']}")
    if query.get("phone"):
        lines.append(f"📞 Number (masked): {query['phone']}")
    if query.get("phone_geo_area"):
        lines.append(f"🌍 Geo Area: {query['phone_geo_area']}")
    if query.get("phone_country"):
        lines.append(f"🗺️ Country: {query['phone_country']}")
    if query.get("phone_carrier"):
        lines.append(f"📡 Carrier: {query['phone_carrier']}")
    if query.get("phone_line_type"):
        lines.append(f"📶 Line Type: {query['phone_line_type']}")

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

    if breach_sources:
        lines.append(f"💾 Breach databases with data: {', '.join(breach_sources)}")
    if geo_sources:
        lines.append(f"📍 Carrier/geo sources: {', '.join(geo_sources)}")
    if scam_sources:
        lines.append(f"🕵️ Scam correlation: {', '.join(scam_sources)}")

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

    lines += [
        "─────────────────────────",
        f"⏱️ Completed in {elapsed}ms",
        f"📅 {report.get('generated_at', '')}",
        "─────────────────────────",
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
            "  /investigate <full name> <phone>\n"
            "  /investigate <phone> <full name>\n\n"
            "Examples:\n"
            "  /investigate +919876543210\n"
            "  /investigate John Doe +919876543210\n\n"
            "Searches public breach databases, phone intelligence, "
            "scam reports, and geolocation sources.\n"
            "All results are from public/breach-intel APIs only."
        )
        return

    full_name, phone = _parse_args(raw)

    if not phone and not full_name:
        await update.message.reply_text("Please provide at least a phone number or a full name.")
        return

    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id, action=ChatAction.TYPING
    )
    await update.message.reply_text("🔍 Running cross-database investigation…")

    try:
        report = await _investigator.investigate(full_name=full_name, phone=phone)
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
        "Send /investigate <phone> or /investigate <name> <phone> to start a new investigation."
    )


def register_investigate_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("investigate", investigate_command))
    application.add_handler(CallbackQueryHandler(_inv_evidence_callback, pattern=r"^inv_evidence:"))
    application.add_handler(CallbackQueryHandler(_inv_export_callback, pattern=r"^inv_export:"))
    application.add_handler(CallbackQueryHandler(_inv_new_callback, pattern=r"^inv_new$"))
