import re
from urllib.parse import urlparse

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatAction
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from config import settings
from middleware.guards import check_text_policy
from services.scanner import ScannerService


scanner = ScannerService(settings.backend_url)

URL_PATTERN = re.compile(r"\b(?:https?://|www\.)[^\s<>()]+", re.IGNORECASE)
BARE_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:"
    r"com|org|net|in|co|io|ai|uk|de|ru|gov|edu|biz|info|app|me|online|site|store|xyz|top|link|click|live|shop|icu|cc"
    r")(?:/[^\s<>()]*)?\b",
    re.IGNORECASE,
)


def _clean_url(raw: str) -> str:
    return raw.strip().rstrip(",.;:!?)\"]'")


def extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    url_spans: list[tuple[int, int]] = []

    for match in URL_PATTERN.finditer(text):
        candidate = _clean_url(match.group(0))
        if not candidate:
            continue
        normalized = candidate.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        urls.append(candidate)
        url_spans.append(match.span())

    def _inside_url_span(start: int, end: int) -> bool:
        for span_start, span_end in url_spans:
            if start >= span_start and end <= span_end:
                return True
        return False

    for match in BARE_DOMAIN_PATTERN.finditer(text):
        start, end = match.span()
        if _inside_url_span(start, end):
            continue

        candidate = _clean_url(match.group(0))
        if not candidate:
            continue
        normalized = candidate.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        urls.append(candidate)

    return urls


def _domain_of(url: str) -> str:
    parse_target = url if re.match(r"^https?://", url, re.IGNORECASE) else f"http://{url}"
    parsed = urlparse(parse_target)
    return parsed.netloc or parsed.path.split("/")[0]


def _shorten_url(url: str, max_len: int = 52) -> str:
    if len(url) <= max_len:
        return url
    return f"{url[:max_len - 1]}…"


def _risk_level_text(risk_level: str) -> str:
    normalized = risk_level.upper()
    if normalized == "HIGH":
        return "🔴 DANGEROUS"
    if normalized == "MEDIUM":
        return "🟠 SUSPICIOUS"
    if normalized == "LOW":
        return "🟢 LOW"
    return "⚪ UNKNOWN"


def _risk_bar(score: int) -> str:
    safe = max(0, min(score, 100))
    filled = max(0, min(10, round(safe / 10)))
    return ("█" * filled) + ("░" * (10 - filled))


def _extract_domain_age(indicators: list[str]) -> str:
    age_regex = re.compile(r"(\d+\s+(?:day|days|month|months|year|years))", re.IGNORECASE)
    for item in indicators:
        match = age_regex.search(item)
        if match:
            return match.group(1)
    return "Unknown"


def _build_url_result_text(
    *,
    url: str,
    domain: str,
    domain_age: str,
    risk_level: str,
    score: int,
    flags: list[str],
    forwarded_note: bool,
) -> str:
    lines = []
    if forwarded_note:
        lines.append("⚠️ Forwarded message detected")
        lines.append("— extra scrutiny applied")
        lines.append("")

    lines.extend(
        [
            "🛡️ Link Analysis",
            "─────────────────",
            f"🔗 URL: {_shorten_url(url)}",
            f"🌐 Domain: {domain}",
            f"📅 Domain Age: {domain_age}",
            "─────────────────",
            f"Risk Score: {score}/100",
            _risk_bar(score),
            f"Level: {_risk_level_text(risk_level)}",
            "─────────────────",
            "🚩 Red Flags:",
        ]
    )

    if flags:
        lines.extend([f"• {flag}" for flag in flags])
    else:
        lines.append("• No major phishing indicators detected")

    lines.extend(
        [
            "─────────────────",
            "⛔ DO NOT click this link" if score >= 60 else "✅ Treat cautiously and verify source",
            "Report: cybercrime.gov.in | 1930",
        ]
    )
    return "\n".join(lines)


def _next_report_id(context: ContextTypes.DEFAULT_TYPE) -> int:
    current = int(context.user_data.get("url_report_seq", 0)) + 1
    context.user_data["url_report_seq"] = current
    return current


def _buttons(report_id: int, high_risk: bool) -> InlineKeyboardMarkup:
    first_row = [InlineKeyboardButton("📊 Full Analysis", callback_data=f"url_full:{report_id}")]
    if high_risk:
        first_row.append(InlineKeyboardButton("🚔 Report This", callback_data=f"url_report:{report_id}"))
    return InlineKeyboardMarkup(
        [
            first_row,
            [InlineKeyboardButton("🔍 Scan Another Link", callback_data="scan_url")],
        ]
    )


def _extract_report_id(callback_data: str | None) -> str:
    data = callback_data or ""
    return data.split(":", maxsplit=1)[1] if ":" in data else ""


async def _analyze_one_url(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    url: str,
    forwarded_note: bool,
) -> None:
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)

    try:
        scan_payload = await scanner.analyze_text(
            content=f"URL submitted for phishing scan: {url}",
            source="telegram",
            external_user_id=str(update.effective_user.id) if update.effective_user else None,
        )
    except Exception as exc:
        await update.message.reply_text(f"Scan failed for {url}: {exc}")
        return

    result = scan_payload.get("result", {})
    score = int(result.get("score", 0) or 0)
    risk_level = str(result.get("risk_level", "unknown"))
    flags = [str(item) for item in result.get("flagged_indicators", [])][:6]
    advice_items = [str(item) for item in result.get("recommended_actions", [])]
    advice = advice_items[0] if advice_items else "Do not interact with suspicious links."

    report_id = _next_report_id(context)
    domain = _domain_of(url)
    domain_age = _extract_domain_age(flags)
    context.user_data[f"url_report:{report_id}"] = {
        "url": url,
        "domain": domain,
        "domain_age": domain_age,
        "risk_level": risk_level,
        "score": score,
        "flags": flags,
        "advice": advice,
        "summary": str(result.get("summary", "")),
        "explanation": str(result.get("explanation", "")),
    }

    rendered = _build_url_result_text(
        url=url,
        domain=domain,
        domain_age=domain_age,
        risk_level=risk_level,
        score=score,
        flags=flags,
        forwarded_note=forwarded_note,
    )
    await update.message.reply_text(
        rendered,
        reply_markup=_buttons(report_id, high_risk=risk_level.upper() == "HIGH"),
    )


async def maybe_handle_url_message(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> bool:
    if not update.message:
        return False

    urls = extract_urls(text)
    if not urls:
        return False

    ok, error_message = check_text_policy(update, text)
    if not ok:
        await update.message.reply_text(error_message)
        return True

    is_forwarded = bool(update.message.forward_origin)
    for url in urls:
        await _analyze_one_url(update, context, url, forwarded_note=is_forwarded)

    context.user_data.pop("scan_mode", None)
    return True


async def url_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return

    text = " ".join(context.args).strip()
    if not text:
        await update.message.reply_text("Usage: /url <link>")
        return

    handled = await maybe_handle_url_message(update, context, text)
    if not handled:
        await update.message.reply_text(
            "No valid URL found. Example: https://example.com or suspicious-domain.com/login"
        )


async def url_full_analysis_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return

    query = update.callback_query
    await query.answer()

    report_id = _extract_report_id(query.data)
    report = context.user_data.get(f"url_report:{report_id}")
    if not report:
        await query.message.reply_text("No analysis report found. Please scan a link first.")
        return

    details = (
        "📊 Full Analysis\n"
        f"URL: {report['url']}\n"
        f"Domain: {report['domain']}\n"
        f"Domain age: {report['domain_age']}\n"
        f"Risk: {_risk_level_text(report['risk_level'])} ({report['score']}/100)\n"
        f"Summary: {report['summary'] or 'No summary available'}\n"
        f"Explanation: {report.get('explanation') or 'No explanation available'}\n"
        "Flags:\n"
        + ("\n".join(f"• {flag}" for flag in report['flags']) if report['flags'] else "• None")
        + f"\nAdvice: {report['advice']}"
    )
    await query.message.reply_text(details)


async def url_report_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return

    query = update.callback_query
    await query.answer()

    report_id = _extract_report_id(query.data)
    report = context.user_data.get(f"url_report:{report_id}")
    url = report["url"] if isinstance(report, dict) and "url" in report else "this link"
    await query.message.reply_text(
        "🚔 Report This\n"
        f"Use cybercrime.gov.in or call 1930 to report {url}.\n"
        "Include screenshots, timestamps, and message source details."
    )


def register_url_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("url", url_command))
    application.add_handler(CallbackQueryHandler(url_full_analysis_callback, pattern=r"^url_full:\d+$"))
    application.add_handler(CallbackQueryHandler(url_report_callback, pattern=r"^url_report:\d+$"))
