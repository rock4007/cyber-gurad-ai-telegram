import hashlib
from typing import Any

import phonenumbers
from phonenumbers import geocoder


AI_SOFTWARE_MARKERS = (
    "midjourney",
    "stable diffusion",
    "dall-e",
    "firefly",
    "comfyui",
    "fooocus",
    "invokeai",
    "automatic1111",
    "dreamstudio",
    "leonardo",
)


def build_artifact_id(kind: str, raw_value: str) -> str:
    normalized_kind = "".join(ch for ch in str(kind).upper() if ch.isalnum())[:6] or "ART"
    digest = hashlib.sha1(str(raw_value).encode("utf-8")).hexdigest()[:10].upper()
    return f"{normalized_kind}-{digest}"


def mask_phone_number(number: str) -> str:
    value = str(number or "").strip()
    if not value:
        return "unknown"

    if value.startswith("+"):
        digits = "".join(ch for ch in value if ch.isdigit())
        if len(digits) <= 6:
            return "+" + digits
        country_len = max(1, len(digits) - 10)
        country_code = digits[:country_len]
        subscriber = digits[country_len:]
        if len(subscriber) <= 4:
            return f"+{country_code}{'*' * len(subscriber)}"
        return f"+{country_code}{'*' * (len(subscriber) - 4)}{subscriber[-4:]}"

    if len(value) <= 4:
        return "*" * len(value)
    return f"{'*' * (len(value) - 4)}{value[-4:]}"


def phone_geo_mask(parsed: phonenumbers.PhoneNumber) -> str:
    country = geocoder.country_name_for_number(parsed, "en") or "Unknown"
    area = geocoder.description_for_number(parsed, "en") or ""
    if area and area != country:
        return f"{area} area, {country}"
    if country != "Unknown":
        return f"{country} only"
    return "Unknown"


def fraction_to_float(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return float(value.numerator) / float(value.denominator)


def exif_gps_to_decimal(dms_values: Any, ref: str) -> float:
    degrees = fraction_to_float(dms_values[0])
    minutes = fraction_to_float(dms_values[1])
    seconds = fraction_to_float(dms_values[2])
    decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
    if ref in ("S", "W"):
        decimal *= -1
    return decimal


def extract_gps_from_exif(exif_data: dict[int, Any]) -> tuple[float | None, float | None]:
    gps_info = exif_data.get(34853)
    if not gps_info:
        return None, None

    lat = gps_info.get(2)
    lat_ref = gps_info.get(1)
    lon = gps_info.get(4)
    lon_ref = gps_info.get(3)
    if not (lat and lat_ref and lon and lon_ref):
        return None, None

    return exif_gps_to_decimal(lat, lat_ref), exif_gps_to_decimal(lon, lon_ref)


def mask_coordinate_area(lat: float | None, lon: float | None) -> str | None:
    if lat is None or lon is None:
        return None
    return f"approx area near {lat:.1f}, {lon:.1f}"


def image_authenticity_assessment(metadata: dict[str, Any]) -> dict[str, Any]:
    software = str(metadata.get("software") or "").strip()
    software_lower = software.lower()
    device = str(metadata.get("device") or "").strip()
    taken_at = str(metadata.get("taken_at") or "").strip()
    gps_found = bool(metadata.get("gps_found"))

    signals: list[str] = []
    if software and software != "No":
        signals.append("Editing or generation software tag present")
    if gps_found:
        signals.append("GPS metadata present")
    if device and device != "Unknown":
        signals.append("Camera or device metadata present")
    if taken_at and taken_at != "Unknown":
        signals.append("Capture timestamp present")
    if not device or device == "Unknown":
        signals.append("Camera metadata missing")

    if any(marker in software_lower for marker in AI_SOFTWARE_MARKERS):
        return {
            "verdict": "possible_ai_generated",
            "confidence": 0.88,
            "signals": signals + ["Software metadata matches known AI generation tooling"],
        }

    if software and software != "No":
        return {
            "verdict": "likely_edited",
            "confidence": 0.74,
            "signals": signals,
        }

    if gps_found or (device and device != "Unknown") or (taken_at and taken_at != "Unknown"):
        return {
            "verdict": "likely_real",
            "confidence": 0.68,
            "signals": signals,
        }

    return {
        "verdict": "inconclusive",
        "confidence": 0.45,
        "signals": signals,
    }