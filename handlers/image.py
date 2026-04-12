import os
import tempfile
import importlib
from datetime import datetime
from typing import Any

import httpx

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatAction
from telegram.ext import Application, CallbackQueryHandler, ContextTypes, MessageHandler, filters

from config import MAX_FILE_SIZE, settings
from middleware.guards import check_text_policy
from services.scanner import ScannerService


scanner = ScannerService(settings.backend_url)

EXIF_GPS_TAG = 34853


def _format_size(size_bytes: int) -> str:
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.2f}MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f}KB"
    return f"{size_bytes}B"


def _fraction_to_float(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return float(value.numerator) / float(value.denominator)


def _dms_to_decimal(dms_values: Any, ref: str) -> float:
    deg = _fraction_to_float(dms_values[0])
    minutes = _fraction_to_float(dms_values[1])
    seconds = _fraction_to_float(dms_values[2])
    decimal = deg + (minutes / 60.0) + (seconds / 3600.0)
    if ref in ("S", "W"):
        decimal *= -1
    return decimal


def _extract_gps(exif_data: dict[int, Any]) -> tuple[float, float] | tuple[None, None]:
    gps_info = exif_data.get(EXIF_GPS_TAG)
    if not gps_info:
        return None, None

    lat = gps_info.get(2)
    lat_ref = gps_info.get(1)
    lon = gps_info.get(4)
    lon_ref = gps_info.get(3)
    if not (lat and lat_ref and lon and lon_ref):
        return None, None

    return _dms_to_decimal(lat, lat_ref), _dms_to_decimal(lon, lon_ref)


def _parse_datetime(exif_data: dict[int, Any]) -> str:
    raw = exif_data.get(36867) or exif_data.get(306)
    if not raw:
        return "Unknown"
    try:
        return datetime.strptime(str(raw), "%Y:%m:%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return str(raw)


def _extract_metadata(path: str) -> dict[str, Any]:
    pil_image_module = importlib.import_module("PIL.Image")
    with pil_image_module.open(path) as image:
        fmt = str(image.format or "Unknown")
        exif_raw = image.getexif() or {}
        exif_data = dict(exif_raw)

    lat, lon = _extract_gps(exif_data)
    device = str(exif_data.get(272) or exif_data.get(271) or "Unknown")
    edited_software = str(exif_data.get(305) or "No")
    taken_at = _parse_datetime(exif_data)

    return {
        "format": fmt,
        "device": device,
        "taken_at": taken_at,
        "edited": "Yes" if edited_software != "No" else "No",
        "software": edited_software,
        "lat": lat,
        "lon": lon,
        "gps_found": lat is not None and lon is not None,
    }


def _estimate_ai_likelihood(result: dict[str, Any], metadata: dict[str, Any]) -> int:
    score = int(result.get("score", 0) or 0)
    base = max(15, min(95, score))
    if metadata.get("edited") == "Yes":
        base = min(98, base + 8)
    return base


async def _reverse_geocode(lat: float, lon: float) -> str | None:
    url = "https://nominatim.openstreetmap.org/reverse"
    params = {
        "format": "jsonv2",
        "lat": f"{lat:.6f}",
        "lon": f"{lon:.6f}",
        "zoom": 16,
    }
    headers = {
        "User-Agent": "CyberGuardAI/1.0 (defensive-security-bot)",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
        payload = response.json()
    except Exception:
        return None

    address = payload.get("address", {}) if isinstance(payload, dict) else {}
    parts = [
        address.get("suburb") or address.get("neighbourhood"),
        address.get("city") or address.get("town") or address.get("village"),
        address.get("state"),
        address.get("country"),
    ]
    label = ", ".join(part for part in parts if part)
    return label or payload.get("display_name")


def _privacy_risk(metadata: dict[str, Any]) -> tuple[str, str]:
    if metadata.get("gps_found"):
        return "HIGH", "This image contains your location!"
    return "LOW", "No location metadata detected."


def _risk_badge(level: str) -> str:
    if level == "HIGH":
        return "⚠️ Privacy Risk: HIGH"
    return "✅ Privacy Risk: LOW"


def _build_image_result_text(
    *,
    filename: str,
    size_bytes: int,
    metadata: dict[str, Any],
    ai_percent: int,
    risk_level: str,
    risk_msg: str,
    hide_coordinates: bool,
) -> str:
    location_line = "⚠️ FOUND" if metadata.get("gps_found") else "Not found"
    gps_line = "GPS: hidden until confirmed"
    if metadata.get("gps_found") and not hide_coordinates:
        gps_line = f"GPS: {metadata['lat']:.4f}, {metadata['lon']:.4f}"
    if not metadata.get("gps_found"):
        gps_line = "GPS: N/A"

    edited_line = metadata.get("edited", "No")
    software = metadata.get("software", "No")
    edited_text = f"{edited_line}"
    if edited_line == "Yes":
        edited_text += f" ({software})"

    return (
        "🛡️ Image Analysis\n"
        "─────────────────\n"
        f"🖼️ Format: {metadata.get('format', 'Unknown')} | Size: {_format_size(size_bytes)}\n"
        "─────────────────\n"
        f"📍 Location Data: {location_line}\n"
        f"{gps_line}\n"
        "─────────────────\n"
        f"📷 Device: {metadata.get('device', 'Unknown')}\n"
        f"📅 Taken: {metadata.get('taken_at', 'Unknown')}\n"
        f"🔧 Edited: {edited_text}\n"
        "─────────────────\n"
        f"🤖 AI Generated: {ai_percent}% likely\n"
        "─────────────────\n"
        f"{_risk_badge(risk_level)}\n"
        f"{risk_msg}"
    )


def _buttons(gps_found: bool, report_id: int) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if gps_found:
        rows.append([InlineKeyboardButton("🗺️ View Location", callback_data=f"img_view_location:{report_id}")])
    rows.append([InlineKeyboardButton("🤖 AI Detection Details", callback_data=f"img_ai_details:{report_id}")])
    rows.append([InlineKeyboardButton("📋 Full Metadata", callback_data=f"img_full_metadata:{report_id}")])
    return InlineKeyboardMarkup(rows)


async def _next_image_report_id(context: ContextTypes.DEFAULT_TYPE) -> int:
    current = int(context.user_data.get("image_report_seq", 0)) + 1
    context.user_data["image_report_seq"] = current
    return current


async def image_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return

    scan_mode = str(context.user_data.get("scan_mode", "")).lower()
    if scan_mode and scan_mode != "image":
        await update.message.reply_text("Please tap the 🖼️ Image button from the scan menu first, then upload an image.")
        return

    photo = update.message.photo[-1] if update.message.photo else None
    if not photo and update.message.document:
        mime_type = (update.message.document.mime_type or "").lower()
        if mime_type.startswith("image/"):
            photo = update.message.document

    if not photo:
        await update.message.reply_text("Please send a photo or image file.")
        return

    file_size = photo.file_size or 0
    if file_size > MAX_FILE_SIZE:
        await update.message.reply_text(f"Image too large ({_format_size(file_size)}). Maximum allowed size is 20 MB.")
        return

    caption_text = update.message.caption or "image upload"
    ok, error_message = check_text_policy(update, caption_text)
    if not ok:
        await update.message.reply_text(error_message)
        return

    tmp_path: str | None = None
    try:
        tg_file = await photo.get_file()
        suffix = ".jpg"
        if update.message.document and update.message.document.file_name and "." in update.message.document.file_name:
            suffix = "." + update.message.document.file_name.rsplit(".", 1)[-1].lower()
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="cgai_img_", suffix=suffix)
        os.close(tmp_fd)
        await tg_file.download_to_drive(tmp_path)

        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)

        metadata = _extract_metadata(tmp_path)

        content = (
            "Image submitted for metadata and forgery analysis. "
            f"filename={update.message.document.file_name if update.message.document else 'telegram_photo'}, "
            f"size_bytes={file_size}, gps_found={metadata.get('gps_found')}, "
            f"device={metadata.get('device')}, edited={metadata.get('edited')}, software={metadata.get('software')}"
        )

        scan_payload = await scanner.analyze_text(
            content=content,
            source="telegram",
            external_user_id=str(update.effective_user.id) if update.effective_user else None,
        )

    except Exception as exc:
        await update.message.reply_text(f"Image analysis failed: {exc}")
        return
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    result = scan_payload.get("result", {}) if isinstance(scan_payload, dict) else {}
    ai_percent = _estimate_ai_likelihood(result, metadata)
    risk_level, risk_msg = _privacy_risk(metadata)
    filename = update.message.document.file_name if update.message.document else "telegram_photo.jpg"

    report_id = await _next_image_report_id(context)
    context.user_data[f"image_report:{report_id}"] = {
        "filename": filename,
        "size": _format_size(file_size),
        "metadata": metadata,
        "ai_percent": ai_percent,
        "risk_level": risk_level,
        "risk_msg": risk_msg,
        "summary": str(result.get("summary", "")),
        "explanation": str(result.get("explanation", "")),
        "score": int(result.get("score", 0) or 0),
        "flags": [str(x) for x in result.get("flagged_indicators", [])],
    }

    # Privacy warning gate before showing coordinates.
    if metadata.get("gps_found"):
        await update.message.reply_text(
            "⚠️ Privacy Warning\n"
            "This image contains GPS coordinates.\n"
            "Location is hidden by default. Tap '🗺️ View Location' to reveal it."
        )

    rendered = _build_image_result_text(
        filename=filename,
        size_bytes=file_size,
        metadata=metadata,
        ai_percent=ai_percent,
        risk_level=risk_level,
        risk_msg=risk_msg,
        hide_coordinates=True,
    )
    context.user_data.pop("scan_mode", None)
    await update.message.reply_text(rendered, reply_markup=_buttons(bool(metadata.get("gps_found")), report_id))


async def _image_view_location_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return
    query = update.callback_query
    await query.answer()

    report_id = (query.data or "").split(":", 1)[-1]
    report = context.user_data.get(f"image_report:{report_id}")
    if not isinstance(report, dict):
        await query.message.reply_text("Location data not found. Please scan again.")
        return

    metadata = report.get("metadata", {})
    lat = metadata.get("lat")
    lon = metadata.get("lon")
    if lat is None or lon is None:
        await query.message.reply_text("No GPS coordinates found in this image.")
        return

    place_label = report.get("location_label")
    if not place_label:
        place_label = await _reverse_geocode(lat, lon)
        if place_label:
            report["location_label"] = place_label

    lines = [
        "🗺️ Location Revealed",
        f"GPS: {lat:.4f}, {lon:.4f}",
    ]
    if place_label:
        lines.append(f"Approx place: {place_label}")
    lines.append(f"Google Maps: https://maps.google.com/?q={lat:.6f},{lon:.6f}")

    await query.message.reply_text("\n".join(lines))


async def _image_ai_details_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return
    query = update.callback_query
    await query.answer()

    report_id = (query.data or "").split(":", 1)[-1]
    report = context.user_data.get(f"image_report:{report_id}")
    if not isinstance(report, dict):
        await query.message.reply_text("AI details not found. Please scan again.")
        return

    flags = report.get("flags", [])
    flags_text = "\n".join(f"• {flag}" for flag in flags) if flags else "• No AI/manipulation indicators"
    await query.message.reply_text(
        "🤖 AI Detection Details\n"
        f"Likelihood: {report.get('ai_percent', 0)}%\n"
        f"Model score: {report.get('score', 0)}/100\n"
        f"Summary: {report.get('summary') or 'No summary'}\n"
        f"Explanation: {report.get('explanation') or 'No explanation'}\n"
        "Signals:\n"
        f"{flags_text}"
    )


async def _image_full_metadata_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return
    query = update.callback_query
    await query.answer()

    report_id = (query.data or "").split(":", 1)[-1]
    report = context.user_data.get(f"image_report:{report_id}")
    if not isinstance(report, dict):
        await query.message.reply_text("Metadata report not found. Please scan again.")
        return

    metadata = report.get("metadata", {})
    gps_text = "Not present"
    if metadata.get("gps_found"):
        gps_text = f"{metadata.get('lat'):.6f}, {metadata.get('lon'):.6f}"
    location_label = report.get("location_label") or "Unknown"

    await query.message.reply_text(
        "📋 Full Metadata\n"
        f"File: {report.get('filename')}\n"
        f"Size: {report.get('size')}\n"
        f"Format: {metadata.get('format', 'Unknown')}\n"
        f"Device: {metadata.get('device', 'Unknown')}\n"
        f"Taken: {metadata.get('taken_at', 'Unknown')}\n"
        f"Edited: {metadata.get('edited', 'No')}\n"
        f"Software: {metadata.get('software', 'No')}\n"
        f"GPS: {gps_text}\n"
        f"Approx place: {location_label}"
    )


def register_image_handlers(application: Application) -> None:
    application.add_handler(MessageHandler(filters.PHOTO | filters.Document.IMAGE, image_command))
    application.add_handler(CallbackQueryHandler(_image_view_location_callback, pattern=r"^img_view_location:\d+$"))
    application.add_handler(CallbackQueryHandler(_image_ai_details_callback, pattern=r"^img_ai_details:\d+$"))
    application.add_handler(CallbackQueryHandler(_image_full_metadata_callback, pattern=r"^img_full_metadata:\d+$"))
