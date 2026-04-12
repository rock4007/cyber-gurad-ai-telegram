import re

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatAction, ParseMode
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from config import settings
from middleware.guards import check_text_policy
from services.scanner import ScannerService


scanner = ScannerService(settings.backend_url)

PHONE_CANDIDATE_PATTERN = re.compile(r"(?:\+\d[\d\-\s()]{6,20}\d|\b\d{10}\b)")
PATTERN_UK = re.compile(r"^\+44\d{10}$")
PATTERN_IN = re.compile(r"^\+91\d{10}$")
PATTERN_RU = re.compile(r"^\+7\d{10}$")
PATTERN_DE = re.compile(r"^\+49\d{10,11}$")
PATTERN_INTL = re.compile(r"^\+\d{7,15}$")
PATTERN_INDIA_LOCAL = re.compile(r"^\d{10}$")


def _normalize_candidate(raw: str) -> str:
    return re.sub(r"[^\d+]", "", raw)


def _extract_phone_candidate(text: str) -> str | None:
    for match in PHONE_CANDIDATE_PATTERN.finditer(text):
        candidate = _normalize_candidate(match.group(0))
        if (
            PATTERN_UK.match(candidate)
            or PATTERN_IN.match(candidate)
            or PATTERN_RU.match(candidate)
            or PATTERN_DE.match(candidate)
            or PATTERN_INTL.match(candidate)
            or PATTERN_INDIA_LOCAL.match(candidate)
        ):
            return candidate
    return None


def _validate_phone(candidate: str) -> tuple[bool, phonenumbers.PhoneNumber | None]:
    try:
        parsed = phonenumbers.parse(candidate, "IN" if candidate.isdigit() else None)
    except phonenumbers.NumberParseException:
        return False, None

    if not phonenumbers.is_possible_number(parsed) or not phonenumbers.is_valid_number(parsed):
        return False, None
    return True, parsed


def _phone_type_label(parsed: phonenumbers.PhoneNumber) -> str:
    kind = phonenumbers.number_type(parsed)
    if kind == PhoneNumberType.MOBILE:
        return "mobile"
    if kind == PhoneNumberType.FIXED_LINE:
        return "landline"
    if kind == PhoneNumberType.FIXED_LINE_OR_MOBILE:
        return "mobile/landline"
    if kind == PhoneNumberType.VOIP:
        return "VoIP"
    return "unknown"


def _risk_meter(score: int) -> str:
    safe_score = max(0, min(score, 100))
    filled = max(0, min(10, round(safe_score / 10)))
    return ("█" * filled) + ("░" * (10 - filled))


def _risk_label(risk_level: str) -> str:
    normalized = risk_level.upper()
    if normalized == "HIGH":
        return "🔴 HIGH"
    if normalized == "MEDIUM":
        return "🟠 MEDIUM"
    if normalized == "LOW":
        return "🟢 LOW"
    return "⚪ UNKNOWN"


def _build_phone_result_text(
    *,
    formatted_number: str,
    country: str,
    carrier_name: str,
    phone_type: str,
    risk_level: str,
    score: int,
    flags: list[str],
    advice: str,
) -> str:
    flag_lines = "\n".join(f"• {flag}" for flag in flags) if flags else "• No major fraud indicators detected"
    return (
        "┌─────────────────────┐\n"
        "🛡️ Phone Scan Result\n"
        "─────────────────────\n"
        f"📞 Number: {formatted_number}\n"
        f"🌍 Country: {country}\n"
        f"📡 Carrier: {carrier_name}\n"
        f"📶 Type: {phone_type}\n"
        "─────────────────────\n"
        f"⚠️ Risk: {_risk_label(risk_level)} ({score}/100)\n"
        f"{_risk_meter(score)}\n"
        "─────────────────────\n"
        "🚩 Flags:\n"
        f"{flag_lines}\n"
        "─────────────────────\n"
        f"💡 Advice: {advice}\n"
        "└─────────────────────┘"
    )


def _result_buttons(is_high_risk: bool) -> InlineKeyboardMarkup:
    first_row = [InlineKeyboardButton("📄 Full Report", callback_data="phone_full_report")]
    if is_high_risk:
        first_row.append(InlineKeyboardButton("🚔 File Complaint", callback_data="phone_file_complaint"))
    return InlineKeyboardMarkup(
        [
            first_row,
            [InlineKeyboardButton("🔍 Scan Another", callback_data="scan_phone")],
        ]
    )


async def _process_phone_text(update: Update, context: ContextTypes.DEFAULT_TYPE, incoming_text: str) -> bool:
    if not update.message:
        return False

    candidate = _extract_phone_candidate(incoming_text)
    if not candidate:
        return False

    ok, error_message = check_text_policy(update, incoming_text)
    if not ok:
        await update.message.reply_text(error_message)
        return True

    valid, parsed = _validate_phone(candidate)
    if not valid or parsed is None:
        await update.message.reply_text(
            "Invalid phone number format.\n"
            "Try one of these examples:\n"
            "- +447700900123\n"
            "- +919876543210\n"
            "- +79991234567\n"
            "- +4915112345678\n"
            "- 9876543210 (India default)"
        )
        return True

    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)

    formatted_e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    formatted_international = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
    )
    region = phonenumbers.region_code_for_number(parsed) or "Unknown"
    carrier_name = carrier.name_for_number(parsed, "en") or "Unknown"
    phone_type = _phone_type_label(parsed)

    try:
        scan_payload = await scanner.analyze_text(
            content=f"Phone number submitted for fraud analysis: {formatted_e164}",
            source="telegram",
            external_user_id=str(update.effective_user.id) if update.effective_user else None,
        )
    except Exception as exc:
        await update.message.reply_text(f"Scan failed: {exc}")
        return True

    result = scan_payload.get("result", {})
    risk_level = str(result.get("risk_level", "unknown"))
    score = int(result.get("score", 0) or 0)
    flags = [str(item) for item in result.get("flagged_indicators", [])][:5]
    recommendations = [str(item) for item in result.get("recommended_actions", [])]
    advice = recommendations[0] if recommendations else "Do not share OTP, passwords, or sensitive data."

    context.user_data["last_phone_report"] = {
        "number": formatted_international,
        "country": geocoder.description_for_number(parsed, "en") or region,
        "carrier": carrier_name,
        "type": phone_type,
        "risk_level": risk_level,
        "score": score,
        "flags": flags,
        "advice": advice,
        "summary": str(result.get("summary", "")),
        "explanation": str(result.get("explanation", "")),
    }

    rendered = _build_phone_result_text(
        formatted_number=formatted_international,
        country=geocoder.description_for_number(parsed, "en") or region,
        carrier_name=carrier_name,
        phone_type=phone_type,
        risk_level=risk_level,
        score=score,
        flags=flags,
        advice=advice,
    )

    await update.message.reply_text(
        rendered,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=_result_buttons(is_high_risk=risk_level.upper() == "HIGH"),
    )
    return True


async def maybe_handle_phone_text(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> bool:
    return await _process_phone_text(update, context, text)


async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return

    text = " ".join(context.args).strip()
    if not text:
        await update.message.reply_text("Usage: /phone <phone_number>")
        return

    await _process_phone_text(update, context, text)


async def phone_full_report_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return
    query = update.callback_query
    await query.answer()

    report = context.user_data.get("last_phone_report")
    if not report:
        await query.message.reply_text("No phone scan report found. Please scan a number first.")
        return

    full_report_text = (
        "📄 Full Phone Report\n"
        f"Number: {report['number']}\n"
        f"Country: {report['country']}\n"
        f"Carrier: {report['carrier']}\n"
        f"Type: {report['type']}\n"
        f"Risk: {_risk_label(report['risk_level'])} ({report['score']}/100)\n"
        f"Summary: {report['summary'] or 'No summary available'}\n"
        f"Explanation: {report.get('explanation') or 'No explanation available'}\n"
        "Flags:\n"
        + ("\n".join(f"• {item}" for item in report["flags"]) if report["flags"] else "• None")
        + f"\nAdvice: {report['advice']}"
    )
    await query.message.reply_text(full_report_text)


async def phone_file_complaint_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return
    query = update.callback_query
    await query.answer()

    await query.message.reply_text(
        "🚔 To file a complaint, submit the number and evidence to your local cybercrime portal or police cyber cell."
    )


def register_phone_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("phone", phone_command))
    application.add_handler(CallbackQueryHandler(phone_full_report_callback, pattern=r"^phone_full_report$"))
    application.add_handler(
        CallbackQueryHandler(phone_file_complaint_callback, pattern=r"^phone_file_complaint$")
    )
