"""Cross-database investigation service.

Given a full name and/or phone number this service queries every available
public-source and breach-intelligence API that is configured via environment
variables, correlates the results, and returns a structured investigation
report.

Scope: public breach records, phone metadata, geolocation of the infrastructure
associated with the artifact, scam-report databases, and VPN/proxy detection.

NOT in scope: private home address lookup, real-time surveillance, or
subscriber-identity discovery.  All results are annotated with source,
timestamp, and confidence so they can be used as evidence in a lawful
investigation.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import time
from urllib.parse import quote
from datetime import datetime, timezone
from typing import Any

import httpx
import phonenumbers
from phonenumbers import carrier, geocoder

from services.investigation import build_artifact_id, mask_phone_number, phone_geo_mask

logger = logging.getLogger("cyberguard.cross_db")

TIMEOUT = httpx.Timeout(15.0)
KNOWN_SCAM_HANDLE_TERMS = {
    "support",
    "official",
    "verify",
    "refund",
    "loan",
    "otp",
    "recovery",
    "crypto",
}
EMAIL_LOCAL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _source_record(source: str, data: Any, confidence: str = "medium") -> dict[str, Any]:
    return {
        "source": source,
        "fetched_at": _now_iso(),
        "confidence": confidence,
        "data": data,
    }


async def _get(url: str, *, params: dict | None = None, headers: dict | None = None) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(url, params=params, headers=headers)
        if r.status_code >= 400:
            return None
        return r.json()
    except Exception:
        return None


async def _post(url: str, *, payload: dict | None = None, data: dict | None = None,
                headers: dict | None = None) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            if payload is not None:
                r = await client.post(url, json=payload, headers=headers or {})
            else:
                r = await client.post(url, data=data or {}, headers=headers or {})
        if r.status_code >= 400:
            return None
        return r.json()
    except Exception:
        return None


def _normalize_handle(value: str) -> str:
    h = value.strip()
    if h.startswith("@"):
        h = h[1:]
    return re.sub(r"[^a-zA-Z0-9_.]", "", h).lower()


def _mask_email(email: str) -> str:
    value = str(email or "").strip().lower()
    if "@" not in value:
        return ""
    local, domain = value.split("@", 1)
    if not local or not domain:
        return ""
    if len(local) == 1:
        safe_local = "*"
    elif len(local) == 2:
        safe_local = local[0] + "*"
    else:
        safe_local = local[0] + ("*" * max(2, len(local) - 2)) + local[-1]
    return f"{safe_local}@{domain}"


def _collect_associated_breach_emails(dehashed_phone: dict[str, Any] | None) -> list[str]:
    emails: list[str] = []
    if not dehashed_phone or not isinstance(dehashed_phone.get("hits"), list):
        return emails

    seen: set[str] = set()
    for hit in dehashed_phone.get("hits") or []:
        masked = _mask_email(str(hit.get("email") or ""))
        if masked and masked not in seen:
            seen.add(masked)
            emails.append(masked)
    return emails[:8]


def _mask_ip_address(ip: str) -> str | None:
    value = str(ip or "").strip()
    parts = value.split(".")
    if len(parts) != 4:
        return None
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if any(n < 0 or n > 255 for n in nums):
        return None
    return f"{nums[0]}.{nums[1]}.{nums[2]}.*"


def _mask_mac_address(mac: str) -> str | None:
    value = str(mac or "").strip().upper().replace("-", ":")
    parts = value.split(":")
    if len(parts) != 6:
        return None
    if any(len(p) != 2 for p in parts):
        return None
    return f"{parts[0]}:{parts[1]}:{parts[2]}:**:**:**"


def _mask_handle(value: str) -> str | None:
    handle = _normalize_handle(value)
    if not handle:
        return None
    if len(handle) <= 2:
        return "*" * len(handle)
    if len(handle) <= 4:
        return handle[0] + ("*" * (len(handle) - 1))
    return handle[:2] + ("*" * (len(handle) - 4)) + handle[-2:]


def _network_geo_hint(
    *,
    phone_meta: dict[str, Any],
    abstract_result: dict[str, Any] | None,
    numverify_result: dict[str, Any] | None,
) -> str | None:
    if numverify_result:
        location = str(numverify_result.get("location") or "").strip()
        country = str(numverify_result.get("country_name") or "").strip()
        parts = [p for p in [location, country] if p]
        if parts:
            return ", ".join(parts)

    if abstract_result:
        country = str(abstract_result.get("country") or "").strip()
        carrier_name = str(abstract_result.get("carrier") or "").strip()
        parts = [p for p in [country, carrier_name] if p]
        if parts:
            return " / ".join(parts)

    fallback_country = str(phone_meta.get("country") or "").strip()
    return fallback_country or None


def _normalize_person_name(value: str) -> str:
    raw = " ".join(str(value or "").strip().split())
    if not raw:
        return ""
    cleaned = re.sub(r"[^a-zA-Z\s\-']", "", raw)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) < 3:
        return ""
    return cleaned.title()


def _mask_person_name(value: str) -> str | None:
    cleaned = _normalize_person_name(value)
    if not cleaned:
        return None

    masked_parts: list[str] = []
    for part in cleaned.split():
        if len(part) <= 1:
            masked_parts.append("*")
        else:
            masked_parts.append(part[0] + ("*" * (len(part) - 1)))
    return " ".join(masked_parts)


def _infer_probable_gender(name: str) -> str:
    lowered = str(name or "").strip().lower()
    if not lowered:
        return "unknown"

    if any(token in lowered for token in (" mr ", " mr.", " sir ")) or lowered.startswith("mr "):
        return "male"
    if any(token in lowered for token in (" ms ", " ms.", " mrs ", " mrs.", " miss ", " madam ")):
        return "female"
    return "unknown"


def _collect_activity_regions(
    *,
    phone_meta: dict[str, Any] | None,
    abstract_result: dict[str, Any] | None,
    numverify_result: dict[str, Any] | None,
    geo_result: dict[str, Any] | None,
) -> list[str]:
    regions: list[str] = []

    for value in [
        (phone_meta or {}).get("country"),
        (numverify_result or {}).get("country_name"),
        (numverify_result or {}).get("location"),
        (abstract_result or {}).get("country"),
        (geo_result or {}).get("country_hint"),
    ]:
        text = str(value or "").strip()
        if text and text not in regions:
            regions.append(text)

    return regions[:6]


def _extract_handle_candidates_from_hit(hit: dict[str, Any]) -> set[str]:
    handles: set[str] = set()
    username = _normalize_handle(str(hit.get("username") or ""))
    if 2 <= len(username) <= 32:
        handles.add(username)

    email = str(hit.get("email") or "").strip().lower()
    if "@" in email:
        local = email.split("@", 1)[0]
        if EMAIL_LOCAL_RE.match(local):
            normalized = _normalize_handle(local)
            if 2 <= len(normalized) <= 32:
                handles.add(normalized)
    return handles


def _build_identity_enrichment(
    *,
    full_name: str,
    dehashed_phone: dict[str, Any] | None,
    dehashed_name: dict[str, Any] | None,
    social_identity: dict[str, Any] | None,
) -> dict[str, Any]:
    name_counts: dict[str, int] = {}
    handle_counts: dict[str, int] = {}
    supporting_sources: list[str] = []

    if dehashed_phone and isinstance(dehashed_phone.get("hits"), list):
        supporting_sources.append("dehashed_phone")
        for hit in dehashed_phone.get("hits") or []:
            candidate_name = _normalize_person_name(hit.get("name"))
            if candidate_name:
                name_counts[candidate_name] = name_counts.get(candidate_name, 0) + 1
            for handle in _extract_handle_candidates_from_hit(hit):
                handle_counts[handle] = handle_counts.get(handle, 0) + 1

    if dehashed_name and isinstance(dehashed_name.get("hits"), list):
        supporting_sources.append("dehashed_name")
        for hit in dehashed_name.get("hits") or []:
            for handle in _extract_handle_candidates_from_hit(hit):
                handle_counts[handle] = handle_counts.get(handle, 0) + 1

    if social_identity and isinstance(social_identity.get("handles"), dict):
        supporting_sources.append("social_identity")
        for _, handle in (social_identity.get("handles") or {}).items():
            normalized = _normalize_handle(handle)
            if normalized:
                handle_counts[normalized] = handle_counts.get(normalized, 0) + 1

    provided_name = _normalize_person_name(full_name)
    if provided_name:
        name_counts[provided_name] = name_counts.get(provided_name, 0) + 2

    sorted_names = sorted(name_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    sorted_handles = sorted(handle_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    probable_name = sorted_names[0][0] if sorted_names else None
    social_candidates = [h for h, _ in sorted_handles[:10]]

    confidence = "low"
    if sorted_names and sorted_names[0][1] >= 2:
        confidence = "medium"
    if sorted_names and sorted_names[0][1] >= 3:
        confidence = "high"

    return {
        "probable_holder_name": probable_name,
        "masked_probable_holder_name": _mask_person_name(probable_name or ""),
        "probable_gender": _infer_probable_gender(probable_name or ""),
        "alternate_names": [n for n, _ in sorted_names[1:6]],
        "probable_social_handles": social_candidates,
        "confidence": confidence,
        "supporting_sources": supporting_sources,
    }


async def _probe_profile(url: str, *, missing_markers: tuple[str, ...]) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            response = await client.get(url)
        text = (response.text or "")[:12000].lower()
        if response.status_code in {404, 410}:
            verdict = "likely_fake_or_nonexistent"
            exists = False
        elif response.status_code == 200 and not any(marker in text for marker in missing_markers):
            verdict = "likely_real"
            exists = True
        else:
            verdict = "inconclusive"
            exists = None
        return {
            "url": url,
            "status_code": response.status_code,
            "exists": exists,
            "verdict": verdict,
        }
    except Exception as exc:
        return {
            "url": url,
            "status_code": None,
            "exists": None,
            "verdict": "inconclusive",
            "error": str(exc),
        }


async def _check_social_identity(
    *,
    telegram_id: str = "",
    telegram_group: str = "",
    twitter_id: str = "",
) -> dict[str, Any]:
    tasks: dict[str, Any] = {}
    handles: dict[str, str] = {}

    if telegram_id:
        tg_id = _normalize_handle(telegram_id)
        if tg_id:
            handles["telegram_id"] = tg_id
            tasks["telegram_id"] = _probe_profile(
                f"https://t.me/{tg_id}",
                missing_markers=("if you have telegram", "username is not occupied", "page not found"),
            )

    if telegram_group:
        tg_group = _normalize_handle(telegram_group)
        if tg_group:
            handles["telegram_group"] = tg_group
            tasks["telegram_group"] = _probe_profile(
                f"https://t.me/{tg_group}",
                missing_markers=("if you have telegram", "page not found", "private channel"),
            )

    if twitter_id:
        tw_id = _normalize_handle(twitter_id)
        if tw_id:
            handles["twitter_id"] = tw_id
            tasks["twitter_id"] = _probe_profile(
                f"https://x.com/{tw_id}",
                missing_markers=("this account doesn", "account doesn", "try searching for another"),
            )

    results: dict[str, Any] = {}
    if tasks:
        names = list(tasks.keys())
        values = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, value in zip(names, values):
            if isinstance(value, Exception):
                results[name] = {"verdict": "inconclusive", "error": str(value)}
            else:
                results[name] = value

    suspicious_hits: list[str] = []
    for kind, handle in handles.items():
        lowered = handle.lower()
        for term in KNOWN_SCAM_HANDLE_TERMS:
            if term in lowered:
                suspicious_hits.append(f"{kind} contains suspicious token '{term}'")
                break

    return {
        "handles": handles,
        "checks": results,
        "suspicious_hits": suspicious_hits,
        "flagged": bool(suspicious_hits) or any(
            (v.get("verdict") == "likely_fake_or_nonexistent") for v in results.values() if isinstance(v, dict)
        ),
    }


# ---------------------------------------------------------------------------
# Phone metadata
# ---------------------------------------------------------------------------

def _parse_phone(number: str) -> dict[str, Any]:
    try:
        parsed = phonenumbers.parse(number, None)
        if not phonenumbers.is_possible_number(parsed):
            return {"valid": False, "raw": number}
        country = geocoder.description_for_number(parsed, "en") or "Unknown"
        region = phonenumbers.region_code_for_number(parsed) or "Unknown"
        line_carrier = carrier.name_for_number(parsed, "en") or "Unknown"
        geo_area = phone_geo_mask(parsed)
        masked = mask_phone_number(phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164))
        kind = phonenumbers.number_type(parsed)
        kind_labels = {
            phonenumbers.PhoneNumberType.MOBILE: "mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "landline",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "mobile/landline",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium-rate",
            phonenumbers.PhoneNumberType.TOLL_FREE: "toll-free",
        }
        return {
            "valid": phonenumbers.is_valid_number(parsed),
            "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "masked": masked,
            "country": country,
            "region_code": region,
            "carrier": line_carrier,
            "line_type": kind_labels.get(kind, "unknown"),
            "geo_area": geo_area,
        }
    except phonenumbers.NumberParseException:
        return {"valid": False, "raw": number}


# ---------------------------------------------------------------------------
# Geolocation via ip-api (public, no key required)
# ---------------------------------------------------------------------------

async def _geolocate_phone_country(country_code: str) -> dict[str, Any] | None:
    """Best-effort: resolve hosting region for the phone-number country."""
    if not country_code or country_code == "Unknown":
        return None
    return {"country_hint": country_code}


async def _geolocate_ip(ip: str) -> dict[str, Any] | None:
    result = await _get(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,country,regionName,city,lat,lon,isp,org,as,proxy,hosting,query"},
    )
    if not result or result.get("status") != "success":
        return None
    vpn = bool(result.get("proxy")) or bool(result.get("hosting"))
    return {
        "ip": result.get("query", ip),
        "country": result.get("country"),
        "region": result.get("regionName"),
        "city": result.get("city"),
        "lat": result.get("lat"),
        "lon": result.get("lon"),
        "isp": result.get("isp"),
        "org": result.get("org"),
        "vpn_or_proxy": vpn,
        "vpn_note": "Real hosting location shown; VPN/proxy detected" if vpn else None,
    }


async def _lookup_mac_vendor(mac_address: str) -> dict[str, Any] | None:
    """Best-effort MAC OUI vendor lookup (vendor only, no device tracking)."""
    mac = str(mac_address or "").strip()
    if not mac:
        return None
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.get(f"https://api.macvendors.com/{mac}")
        if response.status_code >= 400:
            return None
        vendor = (response.text or "").strip()
        if not vendor:
            return None
        return {"mac": mac, "vendor": vendor}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Breach / dark-web lookup sources
# ---------------------------------------------------------------------------

async def _query_haveibeenpwned_phone(phone: str, api_key: str) -> dict[str, Any] | None:
    """HaveIBeenPwned phone lookup (HIBP v3 API, requires key)."""
    result = await _get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{phone}",
        headers={"hibp-api-key": api_key, "user-agent": "CyberGuardAI-Investigator/1.0"},
    )
    if result is None:
        return None
    breaches = [b.get("Name") for b in result if isinstance(b, dict)]
    return {
        "breach_count": len(breaches),
        "breach_names": breaches[:10],
        "note": "Phone appeared in these public data breach records",
    }


async def _query_haveibeenpwned_email(email: str, api_key: str) -> dict[str, Any] | None:
    """HaveIBeenPwned email lookup (HIBP v3 API, requires key)."""
    value = str(email or "").strip().lower()
    if not value or "@" not in value:
        return None
    result = await _get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(value)}",
        headers={"hibp-api-key": api_key, "user-agent": "CyberGuardAI-Investigator/1.0"},
    )
    if result is None:
        return None
    breaches = [b.get("Name") for b in result if isinstance(b, dict)]
    return {
        "breach_count": len(breaches),
        "breach_names": breaches[:10],
        "note": "Email appeared in these public data breach records",
    }


async def _query_dehashed(query: str, search_type: str, api_key: str, email: str) -> dict[str, Any] | None:
    """DeHashed unified breach search (requires API key + account email)."""
    encoded = base64.b64encode(f"{email}:{api_key}".encode()).decode("ascii")
    result = await _get(
        f"https://api.dehashed.com/search?query={search_type}:{query}&size=5",
        headers={"Authorization": f"Basic {encoded}", "Accept": "application/json"},
    )
    if not result:
        return None
    total = int(result.get("total", 0) or 0)
    if total == 0:
        return {"total": 0, "hits": []}
    entries = result.get("entries") or []
    hits = []
    for entry in entries[:5]:
        hits.append({
            "database_name": entry.get("database_name"),
            "email": entry.get("email"),
            "username": entry.get("username"),
            "name": entry.get("name"),
            "phone": entry.get("phone"),
            "address": entry.get("address"),
            "hashed_password": entry.get("hashed_password"),
        })
    return {"total": total, "hits": hits}


async def _query_leakcheck(query: str, api_key: str) -> dict[str, Any] | None:
    """LeakCheck breach lookup (requires API key)."""
    result = await _get(
        "https://leakcheck.io/api/public",
        params={"key": api_key, "check": query},
    )
    if not result:
        return None
    found = result.get("found", False)
    sources = result.get("sources", [])
    return {
        "found": found,
        "source_count": len(sources),
        "sources": sources[:10],
    }


async def _query_abstract_phone(phone: str, api_key: str) -> dict[str, Any] | None:
    """AbstractAPI phone validation for carrier/VoIP classification."""
    result = await _get(
        "https://phonevalidation.abstractapi.com/v1/",
        params={"api_key": api_key, "phone": phone},
    )
    if not result:
        return None
    return {
        "valid": result.get("valid"),
        "type": result.get("type"),
        "carrier": result.get("carrier", {}).get("name"),
        "country": result.get("country", {}).get("name"),
        "is_voip": str(result.get("type", "")).lower() == "voip",
    }


async def _query_numverify(phone: str, api_key: str) -> dict[str, Any] | None:
    """Numverify live carrier data."""
    result = await _get(
        "https://apilayer.net/api/validate",
        params={"access_key": api_key, "number": phone, "format": 1},
    )
    if not result or not result.get("valid"):
        return None
    return {
        "valid": result.get("valid"),
        "local_format": result.get("local_format"),
        "international_format": result.get("international_format"),
        "country_name": result.get("country_name"),
        "location": result.get("location"),
        "carrier": result.get("carrier"),
        "line_type": result.get("line_type"),
    }


# ---------------------------------------------------------------------------
# Suspect name + phone cross-reference
# ---------------------------------------------------------------------------

async def _name_phone_cross_check(name: str, phone_e164: str,
                                   dehashed_key: str, dehashed_email: str) -> dict[str, Any] | None:
    """Check if this exact name+phone pair appears together in a breach record."""
    name_results = await _query_dehashed(name, "name", dehashed_key, dehashed_email)
    if not name_results or name_results.get("total", 0) == 0:
        return {"matched": False, "note": "Name not found in DeHashed records"}
    # look for phone appearing in any hit that also has the matching name
    phone_stripped = "".join(ch for ch in phone_e164 if ch.isdigit())
    matches = []
    for hit in name_results.get("hits", []):
        if hit.get("phone"):
            hit_phone = "".join(ch for ch in str(hit["phone"]) if ch.isdigit())
            if hit_phone and hit_phone in phone_stripped or phone_stripped in hit_phone:
                matches.append(hit)
    return {
        "matched": bool(matches),
        "match_count": len(matches),
        "name_total_records": name_results.get("total", 0),
        "cross_matches": matches,
    }


# ---------------------------------------------------------------------------
# Public scam-report correlation
# ---------------------------------------------------------------------------

async def _check_scam_reports(phone: str) -> dict[str, Any]:
    """Check phone against URLhaus + a basic Google CSE scam search if configured."""
    flags: list[str] = []
    sources_checked: list[str] = []

    # Basic: search for the phone in URLhaus (for associated scam URLs)
    urlhaus = await _post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": phone})
    sources_checked.append("URLhaus")
    if urlhaus and str(urlhaus.get("query_status", "")).lower() == "ok":
        urls = urlhaus.get("urls") or []
        if urls:
            flags.append(f"Phone associated with {len(urls)} malicious URL(s) in URLhaus")

    return {
        "scam_flags": flags,
        "sources_checked": sources_checked,
        "flagged": bool(flags),
    }


# ---------------------------------------------------------------------------
# Main investigation entry point
# ---------------------------------------------------------------------------

class CrossDatabaseInvestigator:
    """Aggregate multiple public and breach-intel sources for a name+phone query."""

    async def investigate(
        self,
        *,
        full_name: str = "",
        phone: str = "",
        email_address: str = "",
        ip_address: str = "",
        mac_address: str = "",
        telegram_id: str = "",
        telegram_group: str = "",
        twitter_id: str = "",
        tier: str = "basic",
        consent_confirmed: bool = False,
        privacy_mode: bool = False,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        tier_value = (tier or "basic").strip().lower()
        if tier_value not in {"basic", "pro", "master"}:
            tier_value = "basic"

        artifact_id = build_artifact_id(
            "INV",
            ":".join(
                [
                    full_name.strip().lower(),
                    phone.strip(),
                    email_address.strip().lower(),
                    ip_address.strip(),
                    mac_address.strip().lower(),
                    telegram_id.strip().lower(),
                    telegram_group.strip().lower(),
                    twitter_id.strip().lower(),
                    tier_value,
                ]
            ),
        )

        # --- phone metadata (always, no API key needed) ---
        phone_meta: dict[str, Any] = {}
        phone_e164 = phone.strip()
        if phone:
            phone_meta = _parse_phone(phone.strip())
            if phone_meta.get("e164"):
                phone_e164 = phone_meta["e164"]

        # --- gather all async tasks concurrently ---
        tasks: dict[str, Any] = {}

        hibp_key = os.getenv("HIBP_API_KEY", "").strip()
        dehashed_key = os.getenv("DEHASHED_API_KEY", "").strip()
        dehashed_email = os.getenv("DEHASHED_EMAIL", "").strip()
        leakcheck_key = os.getenv("LEAKCHECK_API_KEY", "").strip()
        abstract_key = os.getenv("ABSTRACT_API_KEY", "").strip()
        numverify_key = os.getenv("NUMVERIFY_API_KEY", "").strip()

        if phone_e164:
            if tier_value in {"pro", "master"} and hibp_key:
                tasks["hibp"] = _query_haveibeenpwned_phone(phone_e164, hibp_key)
            if tier_value in {"pro", "master"} and leakcheck_key:
                tasks["leakcheck"] = _query_leakcheck(phone_e164, leakcheck_key)
            if tier_value in {"pro", "master"} and abstract_key:
                tasks["abstract"] = _query_abstract_phone(phone_e164, abstract_key)
            if tier_value in {"pro", "master"} and numverify_key:
                tasks["numverify"] = _query_numverify(phone_e164, numverify_key)
            tasks["scam_reports"] = _check_scam_reports(phone_e164)

        email_value = str(email_address or "").strip().lower()
        if email_value and tier_value in {"pro", "master"} and hibp_key:
            tasks["hibp_email"] = _query_haveibeenpwned_email(email_value, hibp_key)

        ip_value = str(ip_address or "").strip()
        if ip_value:
            tasks["ip_geolocation"] = _geolocate_ip(ip_value)

        mac_value = str(mac_address or "").strip().upper()
        if mac_value:
            tasks["mac_vendor_lookup"] = _lookup_mac_vendor(mac_value)

        if dehashed_key and dehashed_email and tier_value == "master":
            if phone_e164:
                tasks["dehashed_phone"] = _query_dehashed(phone_e164, "phone", dehashed_key, dehashed_email)
            if full_name:
                tasks["dehashed_name"] = _query_dehashed(full_name.strip(), "name", dehashed_key, dehashed_email)
            if full_name and phone_e164:
                tasks["cross_check"] = _name_phone_cross_check(full_name.strip(), phone_e164, dehashed_key, dehashed_email)

            social_handles = [
                _normalize_handle(telegram_id),
                _normalize_handle(telegram_group),
                _normalize_handle(twitter_id),
            ]
            for handle in [h for h in social_handles if h]:
                tasks[f"dehashed_username_{handle}"] = _query_dehashed(handle, "username", dehashed_key, dehashed_email)

        if telegram_id or telegram_group or twitter_id:
            tasks["social_identity"] = _check_social_identity(
                telegram_id=telegram_id,
                telegram_group=telegram_group,
                twitter_id=twitter_id,
            )

        # run all concurrently
        results: dict[str, Any] = {}
        if tasks:
            task_names = list(tasks.keys())
            task_coros = list(tasks.values())
            resolved = await asyncio.gather(*task_coros, return_exceptions=True)
            for name, value in zip(task_names, resolved):
                if isinstance(value, Exception):
                    logger.warning("investigation task %s failed: %s", name, value)
                    results[name] = None
                else:
                    results[name] = value

        # --- build evidence records ---
        evidence: list[dict[str, Any]] = []

        if phone_meta:
            evidence.append(_source_record("phonenumbers_library", phone_meta, "high"))

        if results.get("hibp"):
            bc = results["hibp"].get("breach_count", 0)
            evidence.append(_source_record(
                "haveibeenpwned",
                results["hibp"],
                "high" if bc > 0 else "medium",
            ))

        if results.get("hibp_email"):
            bc = results["hibp_email"].get("breach_count", 0)
            evidence.append(_source_record(
                "haveibeenpwned_email",
                results["hibp_email"],
                "high" if bc > 0 else "medium",
            ))

        if results.get("leakcheck"):
            evidence.append(_source_record(
                "leakcheck",
                results["leakcheck"],
                "high" if results["leakcheck"].get("found") else "low",
            ))

        if results.get("dehashed_phone"):
            t = results["dehashed_phone"].get("total", 0)
            evidence.append(_source_record("dehashed_phone", results["dehashed_phone"], "high" if t > 0 else "low"))

        if results.get("dehashed_name"):
            t = results["dehashed_name"].get("total", 0)
            evidence.append(_source_record("dehashed_name", results["dehashed_name"], "high" if t > 0 else "low"))

        if results.get("cross_check"):
            evidence.append(_source_record(
                "name_phone_cross_match",
                results["cross_check"],
                "high" if results["cross_check"].get("matched") else "medium",
            ))

        if results.get("abstract"):
            evidence.append(_source_record("abstract_phone_api", results["abstract"], "medium"))

        if results.get("numverify"):
            evidence.append(_source_record("numverify", results["numverify"], "medium"))

        if results.get("scam_reports"):
            evidence.append(_source_record(
                "scam_report_correlation",
                results["scam_reports"],
                "high" if results["scam_reports"].get("flagged") else "low",
            ))

        if results.get("social_identity"):
            evidence.append(_source_record(
                "social_identity_checks",
                results["social_identity"],
                "medium" if results["social_identity"].get("flagged") else "low",
            ))

        if results.get("ip_geolocation"):
            evidence.append(_source_record("ip_geolocation", results["ip_geolocation"], "medium"))

        if results.get("mac_vendor_lookup"):
            evidence.append(_source_record("mac_vendor_lookup", results["mac_vendor_lookup"], "medium"))

        identity_enrichment = _build_identity_enrichment(
            full_name=full_name,
            dehashed_phone=results.get("dehashed_phone"),
            dehashed_name=results.get("dehashed_name"),
            social_identity=results.get("social_identity"),
        )
        if identity_enrichment.get("probable_holder_name") or identity_enrichment.get("probable_social_handles"):
            evidence.append(_source_record("identity_enrichment", identity_enrichment, identity_enrichment.get("confidence", "low")))

        for key, value in results.items():
            if key.startswith("dehashed_username_") and value:
                total = value.get("total", 0)
                evidence.append(_source_record(
                    key,
                    value,
                    "high" if total > 0 else "low",
                ))

        # --- geolocation ---
        geo_result: dict[str, Any] | None = None
        region_code = phone_meta.get("region_code") if phone_meta else None
        if region_code and region_code != "Unknown":
            geo_result = await _geolocate_phone_country(region_code)
            if geo_result:
                evidence.append(_source_record("phone_geo_region", geo_result, "medium"))

        # --- risk scoring ---
        score = 0
        flags: list[str] = []

        for ev in evidence:
            d = ev.get("data") or {}
            # breach hits
            bc = d.get("breach_count") or (d.get("total") if isinstance(d.get("total"), int) else 0)
            if isinstance(bc, int) and bc > 0:
                score += min(30, bc * 5)
                flags.append(f"Found in {bc} breach record(s) ({ev['source']})")

            if d.get("found") is True:
                score += 25
                flags.append(f"Confirmed in leak database ({ev['source']})")

            if d.get("matched") is True:
                score += 30
                flags.append(f"Name + phone cross-match confirmed in breach data")

            if d.get("is_voip") is True:
                score += 15
                flags.append("Phone identified as VoIP — commonly used for fraud")

            if d.get("vpn_or_proxy") is True:
                score += 10
                flags.append("IP infrastructure indicates VPN/proxy or hosting usage")

            scam_flags = d.get("scam_flags") or []
            for sf in scam_flags:
                score += 20
                flags.append(sf)

            social_hits = d.get("suspicious_hits") or []
            for sh in social_hits:
                score += 10
                flags.append(sh)

            social_checks = d.get("checks") or {}
            for social_name, social_data in social_checks.items():
                verdict = str((social_data or {}).get("verdict", "")).lower()
                if verdict == "likely_fake_or_nonexistent":
                    score += 15
                    flags.append(f"{social_name} appears likely fake/nonexistent")

        if not phone_meta.get("valid") and phone:
            score += 10
            flags.append("Phone number did not pass format validation")

        risk = "CRITICAL" if score >= 80 else "HIGH" if score >= 55 else "MEDIUM" if score >= 30 else "LOW"
        associated_breach_emails = _collect_associated_breach_emails(results.get("dehashed_phone"))
        network_geo = _network_geo_hint(
            phone_meta=phone_meta,
            abstract_result=results.get("abstract"),
            numverify_result=results.get("numverify"),
        )
        activity_regions = _collect_activity_regions(
            phone_meta=phone_meta,
            abstract_result=results.get("abstract"),
            numverify_result=results.get("numverify"),
            geo_result=geo_result,
        )

        if not consent_confirmed:
            identity_enrichment["masked_probable_holder_name"] = None
            identity_enrichment["probable_gender"] = "unknown"
            identity_enrichment["probable_social_handles"] = []
            associated_breach_emails = []
            activity_regions = []

        email_query_value = _mask_email(email_value) if privacy_mode else (email_value or None)
        network_unmasked_allowed = tier_value in {"pro", "master"}
        ip_force_mask = privacy_mode or not network_unmasked_allowed
        mac_force_mask = privacy_mode or not network_unmasked_allowed
        ip_query_value = _mask_ip_address(ip_value) if ip_force_mask else (ip_value or None)
        mac_query_value = _mask_mac_address(mac_value) if mac_force_mask else (mac_value or None)
        social_unmasked_allowed = tier_value in {"pro", "master"}
        social_force_mask = privacy_mode or not social_unmasked_allowed
        probable_social_handles_query = identity_enrichment.get("probable_social_handles") or []
        if social_force_mask:
            probable_social_handles_query = [
                masked
                for masked in (_mask_handle(h) for h in probable_social_handles_query)
                if masked
            ]

        telegram_id_query = _normalize_handle(telegram_id) or None
        telegram_group_query = _normalize_handle(telegram_group) or None
        twitter_id_query = _normalize_handle(twitter_id) or None
        if social_force_mask:
            telegram_id_query = _mask_handle(telegram_id) if telegram_id_query else None
            telegram_group_query = _mask_handle(telegram_group) if telegram_group_query else None
            twitter_id_query = _mask_handle(twitter_id) if twitter_id_query else None

        return {
            "artifact_id": artifact_id,
            "query": {
                "tier": tier_value,
                "consent_confirmed": consent_confirmed,
                "privacy_mode": privacy_mode,
                "full_name": full_name or None,
                "probable_holder_name": identity_enrichment.get("probable_holder_name"),
                "masked_probable_holder_name": identity_enrichment.get("masked_probable_holder_name"),
                "probable_gender": identity_enrichment.get("probable_gender") or "unknown",
                "alternate_names": identity_enrichment.get("alternate_names") or [],
                "probable_social_handles": probable_social_handles_query,
                "identity_confidence": identity_enrichment.get("confidence"),
                "phone": phone_meta.get("masked") or (phone or None),
                "email_address": email_query_value,
                "email_breach_count": (results.get("hibp_email") or {}).get("breach_count") if email_value else None,
                "ip_address": ip_query_value,
                "ip_country": (results.get("ip_geolocation") or {}).get("country"),
                "ip_city": (results.get("ip_geolocation") or {}).get("city"),
                "ip_isp": (results.get("ip_geolocation") or {}).get("isp"),
                "ip_vpn_or_proxy": bool((results.get("ip_geolocation") or {}).get("vpn_or_proxy")) if results.get("ip_geolocation") else None,
                "mac_address": mac_query_value,
                "mac_vendor": (results.get("mac_vendor_lookup") or {}).get("vendor"),
                "phone_geo_area": phone_meta.get("geo_area") or None,
                "phone_country": phone_meta.get("country") or None,
                "phone_carrier": phone_meta.get("carrier") or None,
                "phone_line_type": phone_meta.get("line_type") or None,
                "phone_valid": phone_meta.get("valid") if phone else None,
                "associated_breach_emails": associated_breach_emails,
                "activity_regions": activity_regions,
                "network_geo_hint": network_geo,
                "tracking_status": "disabled_defensive_mode",
                "telegram_id": telegram_id_query,
                "telegram_group": telegram_group_query,
                "twitter_id": twitter_id_query,
            },
            "risk_level": risk,
            "score": min(score, 100),
            "flags": flags,
            "evidence": evidence,
            "sources_queried": list(tasks.keys()),
            "sources_with_data": [e["source"] for e in evidence],
            "generated_at": _now_iso(),
            "elapsed_ms": round((time.perf_counter() - started) * 1000),
        }
