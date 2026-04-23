import re
from urllib.parse import urlparse

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatAction
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from config import settings
from middleware.guards import check_text_policy
from middleware.quota import check_quota, quota_guard
from services.scanner import ScannerService


scanner = ScannerService(settings.backend_url)

HANDLE_PATTERN = re.compile(r"@([a-zA-Z0-9._]{2,32})")
SOCIAL_URL_PATTERN = re.compile(
    r"\b(?:https?://)?(?:www\.)?(facebook\.com|instagram\.com|x\.com|twitter\.com|t\.me|telegram\.me|youtube\.com|wa\.me|linkedin\.com|snapchat\.com|discord\.gg)/[^\s]+",
    re.IGNORECASE,
)

# Local threat intel databases used for quick database checks.
DB_KNOWN_SCAM_HANDLES = {
    "support_refund_team",
    "metamask_supportdesk",
    "bank_kyc_verify_now",
    "loan_fast_approval_24x7",
    "official_otp_reset_team",
}

DB_HIGH_RISK_DOMAINS = {
    "t.me",
    "telegram.me",
    "bit.ly",
    "tinyurl.com",
    "rb.gy",
    "cutt.ly",
}

DB_IMPERSONATION_TERMS = {
    "official support",
    "account verification",
    "kyc urgent",
    "limited time recovery",
    "verify now",
    "security team",
}

DB_FINANCIAL_SCAM_TERMS = {
    "send otp",
    "pay processing fee",
    "crypto doubling",
    "investment guaranteed",
    "instant loan approval",
}


def _looks_like_social_text(text: str) -> bool:
    lowered = text.lower()
    return (
        bool(HANDLE_PATTERN.search(text))
        or bool(SOCIAL_URL_PATTERN.search(text))
        or any(word in lowered for word in ["instagram", "telegram", "facebook", "x.com", "twitter", "whatsapp"])
    )


def _extract_targets(text: str) -> tuple[list[str], list[str], list[str]]:
    handles = sorted({match.group(1).lower() for match in HANDLE_PATTERN.finditer(text)})

    urls: list[str] = []
    domains: list[str] = []
    for match in SOCIAL_URL_PATTERN.finditer(text):
        raw = match.group(0)
        normalized = raw if raw.startswith(("http://", "https://")) else f"https://{raw}"
        urls.append(normalized)

        parsed = urlparse(normalized)
        host = (parsed.netloc or "").lower().replace("www.", "")
        if host:
            domains.append(host)

    return handles, sorted(set(domains)), urls


def _database_checks(text: str, handles: list[str], domains: list[str]) -> list[dict[str, str]]:
    lowered = text.lower()
    hits: list[dict[str, str]] = []

    for handle in handles:
        if handle in DB_KNOWN_SCAM_HANDLES:
            hits.append(
                {
                    "database": "Known Scam Handles DB",
                    "match": f"@{handle}",
                    "reason": "Handle appears in known scam account list",
                }
            )

    for domain in domains:
        if domain in DB_HIGH_RISK_DOMAINS:
            hits.append(
                {
                    "database": "High-Risk Domains DB",
                    "match": domain,
                    "reason": "Short-link or high-abuse domain",
                }
            )

    for term in DB_IMPERSONATION_TERMS:
        if term in lowered:
            hits.append(
                {
                    "database": "Impersonation Phrase DB",
                    "match": term,
                    "reason": "Common social-engineering impersonation phrase",
                }
            )

    for term in DB_FINANCIAL_SCAM_TERMS:
        if term in lowered:
            hits.append(
                {
                    "database": "Financial Scam Pattern DB",
                    "match": term,
                    "reason": "Known payment/OTP scam pattern",
                }
            )

    return hits


def _risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _risk_label(risk_level: str) -> str:
    if risk_level == "HIGH":
        return "🔴 HIGH"
    if risk_level == "MEDIUM":
        return "🟠 MEDIUM"
    return "🟢 LOW"


def _is_master_plan(plan: str | None) -> bool:
    return str(plan or "").strip().lower() in {"full", "master", "enterprise"}


def _buttons(report_id: int, high_risk: bool) -> InlineKeyboardMarkup:
    first_row = [InlineKeyboardButton("📋 Full DB Report", callback_data=f"social_full:{report_id}")]
    if high_risk:
        first_row.append(InlineKeyboardButton("🚔 Report Account", callback_data=f"social_report:{report_id}"))

    return InlineKeyboardMarkup(
        [
            first_row,
            [InlineKeyboardButton("🔎 Scan Another Social Profile", callback_data="scan_social")],
        ]
    )


def _render_result(
    *,
    handles: list[str],
    domains: list[str],
    db_hits: list[dict[str, str]],
    final_score: int,
    final_risk: str,
    plan_name: str = "free",
    agentic_summary: str = "",
) -> str:
    handles_line = ", ".join(f"@{h}" for h in handles[:4]) if handles else "None"
    domains_line = ", ".join(domains[:4]) if domains else "None"

    lines = [
        "🛡️ Social Media Scanner",
        "─────────────────",
        f"Plan: {plan_name.title()}",
        f"Handles: {handles_line}",
        f"Domains: {domains_line}",
        "─────────────────",
        "Database checks: 4/4 completed",
        f"Matches found: {len(db_hits)}",
        f"Risk: {_risk_label(final_risk)} ({final_score}/100)",
        "─────────────────",
        "⚠️ Intelligence Hits:",
    ]

    if db_hits:
        for hit in db_hits[:6]:
            lines.append(f"• [{hit['database']}] {hit['match']} - {hit['reason']}")
    else:
        lines.append("• No direct threat-intel database matches")

    if agentic_summary:
        lines.extend([
            "─────────────────",
            "🧠 Master Agentic Chat Intel:",
            agentic_summary,
        ])

    lines.extend(
        [
            "─────────────────",
            "Always verify account age, followers quality, and payment requests before responding.",
        ]
    )
    return "\n".join(lines)


def _extract_report_id(callback_data: str | None) -> str:
    data = callback_data or ""
    return data.split(":", maxsplit=1)[1] if ":" in data else ""


async def _next_social_report_id(context: ContextTypes.DEFAULT_TYPE) -> int:
    current = int(context.user_data.get("social_report_seq", 0)) + 1
    context.user_data["social_report_seq"] = current
    return current


async def maybe_handle_social_message(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    text: str,
) -> bool:
    if not update.message:
        return False

    scan_mode = str(context.user_data.get("scan_mode", "")).lower()
    should_force = scan_mode == "social"
    if not should_force and not _looks_like_social_text(text):
        return False

    handles, domains, urls = _extract_targets(text)
    if should_force and not (handles or urls):
        await update.message.reply_text(
            "Social scan mode is on. Send a social media handle (like @username) or profile URL."
        )
        return True
    if not handles and not urls:
        return False

    ok, error_message = check_text_policy(update, text)
    if not ok:
        await update.message.reply_text(error_message)
        return True

    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)
    progress = await update.message.reply_text("🔎 Running full social-media database checks...")

    user_plan = "free"
    try:
        if update.effective_user:
            user_plan = await quota_guard.get_plan(
                update.effective_user.id,
                update.effective_user.username,
                update.effective_user.first_name,
            )
    except Exception:
        user_plan = "free"
    is_master = _is_master_plan(user_plan)

    db_hits = _database_checks(text, handles, domains)
    local_score = min(100, len(db_hits) * 22 + (10 if domains else 0))

    ai_score = 0
    ai_summary = ""
    ai_explanation = ""
    try:
        scan_payload = await scanner.analyze_text(
            content=(
                "Social media profile/message submitted for scam analysis. "
                f"text={text}, handles={handles}, domains={domains}"
            ),
            source="telegram",
            external_user_id=str(update.effective_user.id) if update.effective_user else None,
        )
        ai_result = scan_payload.get("result", {})
        ai_score = int(ai_result.get("score", 0) or 0)
        ai_summary = str(ai_result.get("summary", "")).strip()
        ai_explanation = str(ai_result.get("explanation", "")).strip()
    except Exception:
        ai_score = 0
        ai_summary = "AI backend unavailable during this scan."
        ai_explanation = "No explanation available because the AI backend was unavailable during this scan."

    # Master Plan Google Dorking Multi-Layer research
    research = None
    if is_master:
        try:
            from services.full_plan_research import google_dorking_multi_scan
            research = await google_dorking_multi_scan(handles[0] if handles else domains[0] if domains else text[:50], str(update.effective_user.id))
            if research:
                ai_score += research.get('scam_probability', 0)
        except Exception:
            research = {"status": "master_plan_error"}
    else:
        research = {"status": "master_plan_required"}

    agentic = None
    if is_master:
        agentic = await scanner.generate_agentic_chat_insights(
            content=text,
            user_id=str(update.effective_user.id) if update.effective_user else "",
        )

    research_score = int((research or {}).get("scam_probability", 0) or 0)
    agentic_score = int((agentic or {}).get("risk_score", 0) or 0)
    if is_master and research and research.get("status") not in {"master_plan_required", "master_plan_error"}:
        final_score = min(100, round((local_score * 0.45) + (ai_score * 0.3) + (research_score * 0.15) + (agentic_score * 0.1)))
    else:
        final_score = min(100, round((local_score * 0.6) + (ai_score * 0.4)))
    final_risk = _risk_level(final_score)
    report_id = await _next_social_report_id(context)

    context.user_data[f"social_report:{report_id}"] = {
        "text": text,
        "handles": handles,
        "domains": domains,
        "db_hits": db_hits,
        "local_score": local_score,
        "ai_score": ai_score,
        "research": research,
        "final_score": final_score,
        "risk": final_risk,
        "ai_summary": ai_summary,
        "ai_explanation": ai_explanation,
        "plan": user_plan,
        "agentic": agentic,
    }

    await progress.edit_text("✅ Social media database checks complete.")
    await update.message.reply_text(
        _render_result(
            handles=handles,
            domains=domains,
            db_hits=db_hits,
            final_score=final_score,
            final_risk=final_risk,
            plan_name=user_plan,
            agentic_summary=str((agentic or {}).get("intel_summary") or ""),
        ),
        reply_markup=_buttons(report_id, high_risk=final_risk == "HIGH"),
    )

    context.user_data.pop("scan_mode", None)
    return True


@check_quota
async def social_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return

    text = " ".join(context.args).strip()
    if not text:
        await update.message.reply_text(
            "Usage: /social <@handle or social profile URL or suspicious social message>"
        )
        return

    handled = await maybe_handle_social_message(update, context, text)
    if not handled:
        await update.message.reply_text("No social handle/profile detected. Try @username or a profile URL.")


async def social_full_report_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return

    query = update.callback_query
    await query.answer()
    report_id = _extract_report_id(query.data)
    report = context.user_data.get(f"social_report:{report_id}")
    if not isinstance(report, dict):
        await query.message.reply_text("No social report found. Please run a social scan again.")
        return

    db_hits = report.get("db_hits", [])
    hits_text = "\n".join(
        f"• {item['database']}: {item['match']} ({item['reason']})" for item in db_hits
    ) if db_hits else "• None"

    details = (
        "📋 Full Social Scanner Report\n"
        f"Plan: {str(report.get('plan', 'free')).title()}\n"
        f"Risk: {_risk_label(str(report.get('risk', 'LOW')))} ({report.get('final_score', 0)}/100)\n"
        f"Local DB score: {report.get('local_score', 0)}/100\n"
        f"AI score: {report.get('ai_score', 0)}/100\n"
        f"AI summary: {report.get('ai_summary') or 'No summary'}\n"
        f"AI explanation: {report.get('ai_explanation') or 'No explanation'}\n"
        "Database hits:\n"
        f"{hits_text}"
    )
    agentic = report.get("agentic") if isinstance(report.get("agentic"), dict) else None
    if agentic:
        controls = agentic.get("recommended_controls") or []
        controls_text = "\n".join(f"• {str(item)}" for item in controls[:3]) or "• None"
        details += (
            "\n\n🧠 Master Agentic Chat Intel\n"
            f"Summary: {agentic.get('intel_summary', 'N/A')}\n"
            f"Risk Score: {agentic.get('risk_score', 0)}/100\n"
            "Recommended Controls:\n"
            f"{controls_text}"
        )
    await query.message.reply_text(details)


async def social_report_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return

    query = update.callback_query
    await query.answer()

    report_id = _extract_report_id(query.data)
    report = context.user_data.get(f"social_report:{report_id}")
    handle_preview = ""
    if isinstance(report, dict) and report.get("handles"):
        handle_preview = f" about @{report['handles'][0]}"

    await query.message.reply_text(
        "🚔 Report Suspicious Account\n"
        f"You can report this account{handle_preview} to the platform safety team and cybercrime.gov.in (or call 1930).\n"
        "Include profile URL, screenshots, and payment/chat evidence."
    )


def register_social_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("social", social_command))
    application.add_handler(CallbackQueryHandler(social_full_report_callback, pattern=r"^social_full:\d+$"))
    application.add_handler(CallbackQueryHandler(social_report_callback, pattern=r"^social_report:\d+$"))