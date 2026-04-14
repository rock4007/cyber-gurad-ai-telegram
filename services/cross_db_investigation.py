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
import time
from datetime import datetime, timezone
from typing import Any

import httpx
import phonenumbers
from phonenumbers import carrier, geocoder

from services.investigation import build_artifact_id, mask_phone_number, phone_geo_mask

logger = logging.getLogger("cyberguard.cross_db")

TIMEOUT = httpx.Timeout(15.0)


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
    ) -> dict[str, Any]:
        started = time.perf_counter()
        artifact_id = build_artifact_id(
            "INV", f"{full_name.strip().lower()}:{phone.strip()}"
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
            if hibp_key:
                tasks["hibp"] = _query_haveibeenpwned_phone(phone_e164, hibp_key)
            if leakcheck_key:
                tasks["leakcheck"] = _query_leakcheck(phone_e164, leakcheck_key)
            if abstract_key:
                tasks["abstract"] = _query_abstract_phone(phone_e164, abstract_key)
            if numverify_key:
                tasks["numverify"] = _query_numverify(phone_e164, numverify_key)
            tasks["scam_reports"] = _check_scam_reports(phone_e164)

        if dehashed_key and dehashed_email:
            if phone_e164:
                tasks["dehashed_phone"] = _query_dehashed(phone_e164, "phone", dehashed_key, dehashed_email)
            if full_name:
                tasks["dehashed_name"] = _query_dehashed(full_name.strip(), "name", dehashed_key, dehashed_email)
            if full_name and phone_e164:
                tasks["cross_check"] = _name_phone_cross_check(full_name.strip(), phone_e164, dehashed_key, dehashed_email)

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

            scam_flags = d.get("scam_flags") or []
            for sf in scam_flags:
                score += 20
                flags.append(sf)

        if not phone_meta.get("valid") and phone:
            score += 10
            flags.append("Phone number did not pass format validation")

        risk = "CRITICAL" if score >= 80 else "HIGH" if score >= 55 else "MEDIUM" if score >= 30 else "LOW"

        return {
            "artifact_id": artifact_id,
            "query": {
                "full_name": full_name or None,
                "phone": phone_meta.get("masked") or (phone or None),
                "phone_geo_area": phone_meta.get("geo_area") or None,
                "phone_country": phone_meta.get("country") or None,
                "phone_carrier": phone_meta.get("carrier") or None,
                "phone_line_type": phone_meta.get("line_type") or None,
                "phone_valid": phone_meta.get("valid") if phone else None,
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
