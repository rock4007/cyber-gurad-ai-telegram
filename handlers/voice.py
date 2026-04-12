import os
import re
import tempfile
from pathlib import Path

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatAction
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

from config import settings
from middleware.guards import check_text_policy
from services.scanner import ScannerService
from services.transcription import WhisperTranscriptionService


scanner = ScannerService(settings.backend_url)
transcriber = WhisperTranscriptionService()

ACCEPTED_VOICE_FORMATS = {"wav", "mp3", "ogg", "m4a", "opus", "aac", "flac"}

INDIA_SCAM_PHRASES = {
    "aadhaar blocked": "Aadhaar Blocked Scam",
    "sim blocked": "SIM Blocked Scam",
    "digital arrest": "Digital Arrest",
    "ed calling": "ED/CBI Calling",
    "cbi calling": "ED/CBI Calling",
    "kyc update required": "KYC Update Fraud",
    "kyc update": "KYC Update Fraud",
    "you won lottery": "Lottery Scam",
    "investment guaranteed returns": "Investment Scam",
    "guaranteed returns": "Investment Scam",
    "send otp": "OTP Theft",
    "do not tell anyone": "Secrecy Manipulation",
}

UK_SCAM_PHRASES = {
    "hmrc tax refund": "HMRC Tax Refund Scam",
    "amazon account suspended": "Amazon Account Scam",
    "your parcel held": "Parcel Held Scam",
    "bank security team": "Bank Impersonation",
}


def _extract_extension(file_name: str | None, mime_type: str | None, is_voice: bool) -> str:
    if file_name and "." in file_name:
        return file_name.rsplit(".", 1)[-1].lower()
    if mime_type and "/" in mime_type:
        subtype = mime_type.split("/", 1)[-1].lower()
        if subtype == "mpeg":
            return "mp3"
        if subtype == "x-m4a":
            return "m4a"
        return subtype
    return "ogg" if is_voice else "bin"


def _mime_type_for_extension(extension: str) -> str:
    return {
        "mp3": "audio/mpeg",
        "wav": "audio/wav",
        "ogg": "audio/ogg",
        "opus": "audio/ogg",
        "m4a": "audio/mp4",
        "aac": "audio/aac",
        "flac": "audio/flac",
    }.get(extension, "application/octet-stream")


def _next_voice_report_id(context: ContextTypes.DEFAULT_TYPE) -> int:
    current = int(context.user_data.get("voice_report_seq", 0)) + 1
    context.user_data["voice_report_seq"] = current
    return current


def _detect_scam_patterns(transcript: str) -> dict:
    lowered = transcript.lower()
    all_phrases = {**INDIA_SCAM_PHRASES, **UK_SCAM_PHRASES}
    hits: list[dict[str, str]] = []

    for phrase, scam_type in all_phrases.items():
        if phrase in lowered:
            hits.append({"phrase": phrase, "scam_type": scam_type})

    matched_phrases = [hit["phrase"] for hit in hits[:5]]
    scam_type = hits[0]["scam_type"] if hits else "No clear scam type detected"
    confidence = min(98, len(hits) * 22 + (12 if len(hits) >= 2 else 0))

    return {
        "hit_count": len(hits),
        "matched_phrases": matched_phrases,
        "dominant_scam_type": scam_type,
        "confidence": confidence,
    }


def _deepfake_likelihood(analysis: dict, backend_score: int) -> int:
    return min(95, max(12, 10 + analysis["hit_count"] * 8 + round(backend_score * 0.18)))


def _build_voice_result_text(transcript: str, analysis: dict, *, deepfake_percent: int, explanation: str) -> str:
    quoted_transcript = transcript if len(transcript) <= 600 else transcript[:597] + "..."
    phrase_lines = "\n".join(f'• "{phrase}"' for phrase in analysis["matched_phrases"]) or "• None detected"

    lines = [
        "🛡️ Voice Analysis",
        "─────────────────",
        "📝 Transcript:",
        f'"{quoted_transcript}"',
        "─────────────────",
        f"🎭 Deepfake Voice: {deepfake_percent}% likely",
        f"🚨 Scam Type: {analysis['dominant_scam_type']}",
        f"Confidence: {analysis['confidence']}%",
    ]

    if explanation:
        lines.extend([
            "─────────────────",
            "Explanation:",
            explanation,
        ])

    lines.extend([
        "─────────────────",
        "🚩 Suspicious phrases:",
        phrase_lines,
    ])

    if analysis["hit_count"] > 0:
        lines.extend([
            "─────────────────",
            "⛔ This is a SCAM call",
            "Real govt never calls like this",
        ])

    return "\n".join(lines)


async def voice_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return

    voice = update.message.voice
    audio = update.message.audio
    media = voice or audio
    if not media:
        await update.message.reply_text("Please send a voice note or audio file.")
        return

    policy_text = update.message.caption or "voice upload"
    ok, error_message = check_text_policy(update, policy_text)
    if not ok:
        await update.message.reply_text(error_message)
        return

    extension = _extract_extension(getattr(media, "file_name", None), getattr(media, "mime_type", None), bool(voice))
    if extension not in ACCEPTED_VOICE_FORMATS:
        await update.message.reply_text("Accepted audio formats: voice notes, MP3, WAV, OGG, M4A.")
        return

    report_id = _next_voice_report_id(context)
    file_name = getattr(media, "file_name", None) or f"voice_message.{extension}"
    mime_type = getattr(media, "mime_type", None) or _mime_type_for_extension(extension)

    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)
    progress = await update.message.reply_text("🎙️ Transcribing audio... (1/3)")

    temp_path: str | None = None
    try:
        file = await context.bot.get_file(media.file_id)
        temp_dir = tempfile.gettempdir()
        fd, temp_path = tempfile.mkstemp(prefix="cgai_voice_", suffix=f".{extension}", dir=temp_dir)
        os.close(fd)
        await file.download_to_drive(temp_path)

        transcript = await transcriber.transcribe_file(temp_path, mime_type=mime_type)

        await progress.edit_text("🔍 Detecting scam patterns... (2/3)")
        analysis = _detect_scam_patterns(transcript)

        await progress.edit_text("🧠 AI analysis... (3/3)")
        scan_payload = await scanner.analyze_text(
            content=(
                "Voice transcript submitted for scam analysis. "
                f"transcript={transcript}"
            ),
            source="telegram",
            external_user_id=str(update.effective_user.id) if update.effective_user else None,
        )

        result = scan_payload.get("result", {}) if isinstance(scan_payload, dict) else {}
        backend_score = int(result.get("score", 0) or 0)
        explanation = str(result.get("explanation", "")).strip() or str(result.get("summary", "")).strip()
        local_confidence = analysis["confidence"]
        analysis["confidence"] = max(local_confidence, min(99, round((local_confidence * 0.6) + (backend_score * 0.4))))
        deepfake_percent = _deepfake_likelihood(analysis, backend_score)

        context.user_data[f"voice_report:{report_id}"] = {
            "transcript": transcript,
            "analysis": analysis,
            "deepfake_percent": deepfake_percent,
            "explanation": explanation,
            "file_name": file_name,
        }

        keyboard = InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("📄 Full Transcript", callback_data=f"voice_transcript:{report_id}")],
                [InlineKeyboardButton("🚔 Report This Call", callback_data=f"voice_report:{report_id}")],
                [InlineKeyboardButton("ℹ️ About This Scam Type", callback_data=f"voice_info:{report_id}")],
            ]
        )

        await progress.edit_text(
            _build_voice_result_text(
                transcript,
                analysis,
                deepfake_percent=deepfake_percent,
                explanation=explanation,
            ),
            reply_markup=keyboard,
        )
    except Exception as exc:
        await progress.edit_text(f"⚠️ Voice scan failed: {exc}")
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


async def _voice_transcript_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return
    query = update.callback_query
    await query.answer()

    report_id = (query.data or "").split(":", 1)[-1]
    report = context.user_data.get(f"voice_report:{report_id}")
    if not isinstance(report, dict):
        await query.message.reply_text("Transcript not found. Please scan the audio again.")
        return

    transcript = str(report.get("transcript", "")).strip() or "No transcript available."
    explanation = str(report.get("explanation", "")).strip()
    text = ["📄 Full Transcript", "", f'"{transcript}"']
    if explanation:
        text.extend(["", "Explanation:", explanation])
    await query.message.reply_text("\n".join(text))


async def _voice_report_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return
    query = update.callback_query
    await query.answer()

    await query.message.reply_text(
        "🚔 Report This Scam Call\n"
        "India: call 1930 or report on cybercrime.gov.in\n"
        "UK: report to Action Fraud at 0300 123 2040\n"
        "Share the caller ID, time of call, transcript, and any follow-up messages."
    )


async def _voice_info_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return
    query = update.callback_query
    await query.answer()

    report_id = (query.data or "").split(":", 1)[-1]
    report = context.user_data.get(f"voice_report:{report_id}")
    scam_type = "Suspicious voice scam"
    if isinstance(report, dict):
        analysis = report.get("analysis", {})
        scam_type = str(analysis.get("dominant_scam_type", scam_type))

    await query.message.reply_text(
        "ℹ️ About This Scam Type\n"
        f"Type: {scam_type}\n"
        "Protect yourself:\n"
        "• Hang up and call the organization back using an official number\n"
        "• Never share OTPs, PINs, Aadhaar, PAN, or banking details\n"
        "• Never install apps or follow remote-access instructions from callers\n"
        "• Warn family members if this caller is impersonating a bank or government agency"
    )


def register_voice_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("voice", voice_command))
    application.add_handler(MessageHandler(filters.VOICE | filters.AUDIO, voice_command))
    application.add_handler(CallbackQueryHandler(_voice_transcript_callback, pattern=r"^voice_transcript:\d+$"))
    application.add_handler(CallbackQueryHandler(_voice_report_callback, pattern=r"^voice_report:\d+$"))
    application.add_handler(CallbackQueryHandler(_voice_info_callback, pattern=r"^voice_info:\d+$"))

