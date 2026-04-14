import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import phonenumbers
from anthropic import AsyncAnthropic
from phonenumbers import carrier, geocoder
from PIL import Image

from config import SCAN_TIMEOUT, settings
from services.investigation import (
    build_artifact_id,
    extract_gps_from_exif,
    image_authenticity_assessment,
    mask_coordinate_area,
    mask_phone_number,
    phone_geo_mask,
)
from services.origin_intel import OriginIntelligenceService
from services.transcription import WhisperTranscriptionService


logger = logging.getLogger("cyberguard.scanner")


class AsyncScannerService:
    def __init__(self, backend_url: str | None = None) -> None:
        self.backend_url = backend_url.rstrip("/") if backend_url else ""
        self.timeout = httpx.Timeout(SCAN_TIMEOUT)
        self.transcriber = WhisperTranscriptionService()
        self._claude = AsyncAnthropic(api_key=settings.anthropic_api_key)
        self.google_safe_browsing_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
        self.abstract_phone_key = os.getenv("ABSTRACT_API_KEY", "").strip()
        self.urlhaus_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        self.origin_intel = OriginIntelligenceService()
        self.full_plan_research = True

    def _safe_result(self, scan_type: str) -> dict[str, Any]:
        return {
            "scan_type": scan_type,
            "risk_level": "LOW",
            "score": 0,
            "summary": "No risk signals detected.",
            "flags": [],
            "details": {},
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    async def _http_get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, params=params, headers=headers)
            if response.status_code >= 400:
                return None
            return response.json()
        except Exception:
            return None

    async def _http_post_json(
        self,
        url: str,
        *,
        payload: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                if payload is not None:
                    response = await client.post(url, json=payload, headers=headers)
                else:
                    response = await client.post(url, data=data, headers=headers)
            if response.status_code >= 400:
                return None
            return response.json()
        except Exception:
            return None

    async def scan_phone(self, number: str, user_id: str) -> dict:
        started = time.perf_counter()
        logger.info("scan_phone started user_id=%s", user_id)
        fallback = self._safe_result("phone")
        try:
            parsed = phonenumbers.parse(number, None)
            is_valid = phonenumbers.is_valid_number(parsed)
            normalized_number = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            region = phonenumbers.region_code_for_number(parsed) or "Unknown"
            country = geocoder.description_for_number(parsed, "en") or region
            telco = carrier.name_for_number(parsed, "en") or "Unknown"
            artifact_id = build_artifact_id("PHN", normalized_number)
            masked_number = mask_phone_number(normalized_number)
            geo_mask = phone_geo_mask(parsed)

            abstract_data = None
            if self.abstract_phone_key:
                abstract_data = await self._http_get_json(
                    "https://phonevalidation.abstractapi.com/v1/",
                    params={"api_key": self.abstract_phone_key, "phone": number, "user_id": user_id},
                )

            breach_hits: list[str] = []
            dehashed_key = os.getenv("DEHASHED_API_KEY", "").strip()
            dehashed_email = os.getenv("DEHASHED_EMAIL", "").strip()
            if dehashed_key and dehashed_email:
                # DeHashed does not support phone on all plans; this is best-effort.
                breach_payload = await self._http_get_json(
                    f"https://api.dehashed.com/search?query=phone:{number}&size=1",
                    headers={
                        "Authorization": "Basic "
                        + (
                            __import__("base64")
                            .b64encode(f"{dehashed_email}:{dehashed_key}".encode("utf-8"))
                            .decode("ascii")
                        )
                    },
                )
                if breach_payload and int(breach_payload.get("total", 0) or 0) > 0:
                    breach_hits.append("Phone found in exposed records dataset")

            score = 0
            flags: list[str] = []
            if not is_valid:
                score += 20
                flags.append("Invalid or malformed number")
            if abstract_data and not bool(abstract_data.get("valid", True)):
                score += 20
                flags.append("Abstract phone API marked number invalid")
            if breach_hits:
                score += 35
                flags.extend(breach_hits)

            # --- Origin intelligence ---
            origin = await self.origin_intel.resolve(phone=number)

            risk = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
            return {
                "scan_type": "phone",
                "risk_level": risk,
                "score": min(score, 100),
                "summary": "Phone scan complete.",
                "flags": flags,
                "details": {
                    "input": number,
                    "normalized": normalized_number,
                    "artifact_id": artifact_id,
                    "identity_label": artifact_id,
                    "identity_confidence": "unknown",
                    "masked_number": masked_number,
                    "geo_mask": geo_mask,
                    "is_valid": is_valid,
                    "country": country,
                    "carrier": telco,
                    "abstract": abstract_data or {},
                    "breach_hits": breach_hits,
                    "origin_intelligence": origin,
                },
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        except Exception as exc:
            logger.exception("scan_phone failed user_id=%s: %s", user_id, exc)
            return fallback
        finally:
            logger.info("scan_phone finished user_id=%s in %.2fms", user_id, (time.perf_counter() - started) * 1000)

    async def scan_url(self, url: str, user_id: str) -> dict:
        started = time.perf_counter()
        logger.info("scan_url started user_id=%s", user_id)
        fallback = self._safe_result("url")
        try:
            flags: list[str] = []
            score = 0

            safe_browsing_hit = False
            if self.google_safe_browsing_key:
                payload = {
                    "client": {"clientId": "cyberguard-ai", "clientVersion": "1.0", "userId": user_id},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                }
                sb = await self._http_post_json(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_safe_browsing_key}",
                    payload=payload,
                )
                if sb and sb.get("matches"):
                    safe_browsing_hit = True
                    score += 45
                    flags.append("Google Safe Browsing flagged this URL")

            domain = url.replace("http://", "").replace("https://", "").split("/", 1)[0].lower()
            whois_info = await self._http_get_json(
                f"https://rdap.org/domain/{domain}",
                params={"user_id": user_id},
            )
            domain_age_days = None
            if whois_info:
                events = whois_info.get("events", [])
                created = next((e.get("eventDate") for e in events if e.get("eventAction") == "registration"), None)
                if created:
                    try:
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        domain_age_days = (datetime.now(created_dt.tzinfo) - created_dt).days
                        if domain_age_days < 30:
                            score += 20
                            flags.append("Very new domain age")
                    except Exception:
                        pass

            typo_result = {}
            try:
                import tldextract  # type: ignore

                ext = tldextract.extract(domain)
                label = (ext.domain or "").lower()
                suspicious_tokens = {"paypa1", "micros0ft", "faceb00k", "amaz0n", "g00gle"}
                typo_result = {"domain_label": label, "possible_typosquat": label in suspicious_tokens}
                if typo_result["possible_typosquat"]:
                    score += 25
                    flags.append("Potential typosquatting pattern")
            except Exception:
                typo_result = {"available": False}

            urlhaus = await self._http_post_json(
                self.urlhaus_endpoint,
                data={"url": url, "user_id": user_id},
            )
            urlhaus_hit = bool(urlhaus and str(urlhaus.get("query_status", "")).lower() == "ok")
            if urlhaus_hit:
                score += 40
                flags.append("URLhaus lists this URL as malicious")

            # --- Origin intelligence ---
            origin = await self.origin_intel.resolve(url=url)
            if origin.get("best_estimate", {}).get("vpn_detected"):
                score += 10
                flags.append("Server hosted behind VPN/proxy — real location resolved")

            risk = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
            return {
                "scan_type": "url",
                "risk_level": risk,
                "score": min(score, 100),
                "summary": "URL scan complete.",
                "flags": flags,
                "details": {
                    "url": url,
                    "domain": domain,
                    "safe_browsing_hit": safe_browsing_hit,
                    "domain_age_days": domain_age_days,
                    "typosquatting": typo_result,
                    "urlhaus": urlhaus or {},
                    "origin_intelligence": origin,
                },
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        except Exception as exc:
            logger.exception("scan_url failed user_id=%s: %s", user_id, exc)
            return fallback
        finally:
            logger.info("scan_url finished user_id=%s in %.2fms", user_id, (time.perf_counter() - started) * 1000)

    async def scan_file(self, filepath: str, user_id: str) -> dict:
        started = time.perf_counter()
        logger.info("scan_file started user_id=%s", user_id)
        fallback = self._safe_result("file")
        try:
            path = Path(filepath)
            if not path.exists() or not path.is_file():
                return fallback

            md5_hasher = hashlib.md5()
            sha256_hasher = hashlib.sha256()
            with path.open("rb") as fh:
                while chunk := fh.read(65536):
                    md5_hasher.update(chunk)
                    sha256_hasher.update(chunk)
            md5_hash = md5_hasher.hexdigest()
            sha256_hash = sha256_hasher.hexdigest()

            vt_data = None
            vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
            if vt_key:
                vt_data = await self._http_get_json(
                    f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
                    headers={"x-apikey": vt_key, "x-user-id": user_id},
                )

            yara_matches: list[str] = []
            try:
                import yara  # type: ignore

                yara_rule_path = os.getenv("YARA_RULES_PATH", "").strip()
                if yara_rule_path and Path(yara_rule_path).exists():
                    rules = yara.compile(filepath=yara_rule_path)
                    matches = rules.match(filepath)
                    yara_matches = [m.rule for m in matches]
            except Exception:
                yara_matches = []

            pe_info: dict[str, Any] = {}
            if path.suffix.lower() == ".exe":
                try:
                    import pefile  # type: ignore

                    pe = pefile.PE(filepath)
                    pe_info = {
                        "machine": int(getattr(pe.FILE_HEADER, "Machine", 0)),
                        "sections": len(getattr(pe, "sections", [])),
                        "imports_present": bool(getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)),
                    }
                except Exception:
                    pe_info = {"available": False}

            score = 0
            flags: list[str] = []
            if vt_data:
                stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0) or 0)
                suspicious = int(stats.get("suspicious", 0) or 0)
                if malicious or suspicious:
                    score += min(60, malicious * 6 + suspicious * 3)
                    flags.append(f"VirusTotal: malicious={malicious}, suspicious={suspicious}")

            if yara_matches:
                score += min(30, len(yara_matches) * 8)
                flags.append(f"YARA matched {len(yara_matches)} rule(s)")

            if pe_info and path.suffix.lower() == ".exe":
                score += 5

            risk = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
            return {
                "scan_type": "file",
                "risk_level": risk,
                "score": min(score, 100),
                "summary": "File scan complete.",
                "flags": flags,
                "details": {
                    "filepath": str(path),
                    "md5": md5_hash,
                    "sha256": sha256_hash,
                    "virustotal": vt_data or {},
                    "yara_matches": yara_matches,
                    "pe_analysis": pe_info,
                },
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        except Exception as exc:
            logger.exception("scan_file failed user_id=%s: %s", user_id, exc)
            return fallback
        finally:
            logger.info("scan_file finished user_id=%s in %.2fms", user_id, (time.perf_counter() - started) * 1000)

    async def scan_image(self, filepath: str, user_id: str) -> dict:
        started = time.perf_counter()
        logger.info("scan_image started user_id=%s", user_id)
        fallback = self._safe_result("image")
        try:
            path = Path(filepath)
            if not path.exists() or not path.is_file():
                return fallback

            gps_found = False
            exif_summary: dict[str, Any] = {}
            with Image.open(path) as img:
                exif = img.getexif() or {}
                exif_data = dict(exif)
                gps = exif_data.get(34853)
                gps_found = bool(gps)
                lat, lon = extract_gps_from_exif(exif_data)
                software = exif_data.get(305)
                taken_at = exif_data.get(36867) or exif_data.get(306)
                exif_summary = {
                    "format": img.format,
                    "size": img.size,
                    "camera": exif_data.get(272) or exif_data.get(271),
                    "device": exif_data.get(272) or exif_data.get(271) or "Unknown",
                    "gps_found": gps_found,
                    "lat": lat,
                    "lon": lon,
                    "software": str(software or "No"),
                    "taken_at": str(taken_at or "Unknown"),
                }

            authenticity = image_authenticity_assessment(exif_summary)
            artifact_id = build_artifact_id("IMG", f"{path.name}:{path.stat().st_size}:{path.stat().st_mtime_ns}")
            score = 25 if gps_found else 0
            flags = ["GPS metadata present"] if gps_found else []
            verdict = str(authenticity.get("verdict", "inconclusive"))
            if verdict == "possible_ai_generated":
                score = max(score, 55)
                flags.append("Authenticity signals suggest AI-generated content")
            elif verdict == "likely_edited":
                score = max(score, 35)
                flags.append("Image metadata suggests prior editing")

            risk = "MEDIUM" if gps_found else "LOW"
            if score >= 40:
                risk = "MEDIUM"
            return {
                "scan_type": "image",
                "risk_level": risk,
                "score": score,
                "summary": "Image metadata scan complete.",
                "flags": flags,
                "details": {
                    "filepath": str(path),
                    "artifact_id": artifact_id,
                    "masked_area": mask_coordinate_area(exif_summary.get("lat"), exif_summary.get("lon")),
                    "authenticity": authenticity,
                    "exif": exif_summary,
                },
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        except Exception as exc:
            logger.exception("scan_image failed user_id=%s: %s", user_id, exc)
            return fallback
        finally:
            logger.info("scan_image finished user_id=%s in %.2fms", user_id, (time.perf_counter() - started) * 1000)

    async def scan_voice(self, filepath: str, user_id: str) -> dict:
        started = time.perf_counter()
        logger.info("scan_voice started user_id=%s", user_id)
        fallback = self._safe_result("voice")
        try:
            path = Path(filepath)
            if not path.exists() or not path.is_file():
                return fallback

            transcript = await self.transcriber.transcribe_file(str(path), mime_type="audio/ogg")
            analysis = await self._claude.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=260,
                temperature=0,
                system=(
                    "You are a defensive scam analyst. Return JSON with keys "
                    "risk_level, score, summary, flags."
                ),
                messages=[
                    {
                        "role": "user",
                        "content": f"user_id={user_id}\nAnalyze this transcript for scam patterns:\n{transcript}",
                    }
                ],
            )
            raw = "\n".join(str(getattr(chunk, "text", "")) for chunk in (analysis.content or [])).strip()
            parsed: dict[str, Any]
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = {
                    "risk_level": "MEDIUM",
                    "score": 45,
                    "summary": "Voice transcript analyzed.",
                    "flags": ["Classifier returned non-JSON output"],
                }

            return {
                "scan_type": "voice",
                "risk_level": str(parsed.get("risk_level", "LOW")).upper(),
                "score": int(parsed.get("score", 0) or 0),
                "summary": str(parsed.get("summary", "Voice scan complete.")),
                "flags": [str(item) for item in parsed.get("flags", [])],
                "details": {
                    "filepath": str(path),
                    "transcript": transcript,
                },
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        except Exception as exc:
            logger.exception("scan_voice failed user_id=%s: %s", user_id, exc)
            return fallback
        finally:
            logger.info("scan_voice finished user_id=%s in %.2fms", user_id, (time.perf_counter() - started) * 1000)

    async def generate_report(self, scan_data: dict) -> str:
        started = time.perf_counter()
        logger.info("generate_report started")
        try:
            response = await self._claude.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=500,
                temperature=0,
                system=(
                    "You are a defensive cybersecurity reporting assistant. "
                    "Write a concise human-readable threat report with risk, evidence, and next steps."
                ),
                messages=[
                    {
                        "role": "user",
                        "content": f"Generate a report for this scan data:\n{json.dumps(scan_data, ensure_ascii=False)}",
                    }
                ],
            )
            text = "\n".join(str(getattr(chunk, "text", "")) for chunk in (response.content or [])).strip()
            return text or "No report generated."
        except Exception as exc:
            logger.exception("generate_report failed: %s", exc)
            return "Threat report is temporarily unavailable."
        finally:
            logger.info("generate_report finished in %.2fms", (time.perf_counter() - started) * 1000)


class ScannerService(AsyncScannerService):
    """Backward-compatible scanner facade used by existing handlers."""

    async def analyze_text(
        self,
        *,
        content: str,
        source: str,
        external_user_id: str | None,
    ) -> dict:
        if not self.backend_url:
            raise RuntimeError("backend_url is required for analyze_text")

        endpoint = f"{self.backend_url}/v1/scan"
        payload = {
            "source": source,
            "content": content,
            "consent_confirmed": True,
            "external_user_id": external_user_id,
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(endpoint, json=payload)

        if response.status_code >= 400:
            raise RuntimeError(
                f"Backend scan failed ({response.status_code}): {response.text[:200]}"
            )

        return response.json()
