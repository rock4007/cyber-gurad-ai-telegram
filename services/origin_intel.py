"""Origin intelligence service for CyberGuard AI.

Correlates multiple data-points extracted from user-submitted scam content
(domains, IPs, phone numbers) to estimate the real geographic origin of a
threat actor — even when they hide behind VPNs, proxies, or CDNs.

This is **defensive analysis of submitted content**, not user tracking.
"""

import asyncio
import logging
import re
import socket
from typing import Any

import httpx
import phonenumbers
from phonenumbers import geocoder

from config import settings

logger = logging.getLogger("cyberguard.origin_intel")

TIMEOUT = httpx.Timeout(12.0)

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)


class OriginIntelligenceService:
    """Resolve the real location behind content artifacts."""

    async def resolve(
        self,
        *,
        url: str | None = None,
        phone: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        """Return a merged origin-intelligence report from all available signals."""
        signals: list[dict[str, Any]] = []
        tasks: list[tuple[str, Any]] = []

        if url:
            domain = self._extract_domain(url)
            if domain:
                tasks.append(("domain_hosting", self._resolve_domain(domain)))

        if phone:
            tasks.append(("phone_origin", self._resolve_phone(phone)))

        if ip:
            tasks.append(("ip_geolocation", self._geolocate_ip(ip)))

        if url and not ip:
            domain = self._extract_domain(url)
            if domain:
                tasks.append(("dns_real_ip", self._resolve_domain_real_ip(domain)))

        if tasks:
            labels, coros = zip(*tasks)
            results = await asyncio.gather(*coros, return_exceptions=True)
            for label, result in zip(labels, results):
                if isinstance(result, Exception):
                    logger.warning("origin_intel %s failed: %s", label, result)
                    continue
                if result:
                    signals.append({"source": label, **result})

        best = self._correlate(signals)
        return {
            "origin_signals": signals,
            "best_estimate": best,
        }

    # ------------------------------------------------------------------
    # Individual resolvers
    # ------------------------------------------------------------------

    async def _geolocate_ip(self, ip: str) -> dict[str, Any] | None:
        """Enhanced IP geo with AbuseIPDB (Full Plan) + Google Geocoding fallback + free ip-api."""
        result = {}
        # Full Plan AbuseIPDB darkweb/abuse
        if settings.abuseipdb_api_key:
            from services.full_plan_research import abuseipdb_check

            abuse = await abuseipdb_check(ip, "bot")
            if abuse:
                result["abuseipdb"] = abuse
        # Free ip-api
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as,proxy,hosting")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    result.update({
                        "ip": ip,
                        "country": data.get("country"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as_number": data.get("as"),
                        "is_proxy_or_vpn": bool(data.get("proxy")),
                        "is_hosting": bool(data.get("hosting")),
                    })
        return result or None

    async def _resolve_domain(self, domain: str) -> dict[str, Any] | None:
        """Resolve domain hosting IP then geolocate it."""
        ip = await asyncio.to_thread(self._dns_resolve, domain)
        if not ip:
            return None
        geo = await self._geolocate_ip(ip)
        if not geo:
            return {"domain": domain, "resolved_ip": ip}
        geo["domain"] = domain
        return geo

    async def _resolve_domain_real_ip(self, domain: str) -> dict[str, Any] | None:
        """Try to find the real server IP behind CDN/VPN by checking common
        subdomains that often bypass reverse proxies."""
        candidates = [
            f"mail.{domain}",
            f"ftp.{domain}",
            f"cpanel.{domain}",
            f"webmail.{domain}",
            f"direct.{domain}",
            f"origin.{domain}",
        ]
        found_ips: list[str] = []
        for sub in candidates:
            ip = await asyncio.to_thread(self._dns_resolve, sub)
            if ip and ip not in found_ips:
                found_ips.append(ip)

        if not found_ips:
            return None

        geo = await self._geolocate_ip(found_ips[0])
        if geo:
            geo["method"] = "subdomain_bypass"
            geo["checked_subdomains"] = candidates
            geo["discovered_ips"] = found_ips
        return geo

    async def _resolve_phone(self, number: str) -> dict[str, Any] | None:
        """Get origin country/region from phone number metadata."""
        try:
            parsed = phonenumbers.parse(number, None)
        except phonenumbers.NumberParseException:
            return None

        country = geocoder.description_for_number(parsed, "en") or None
        region_code = phonenumbers.region_code_for_number(parsed) or None

        return {
            "phone": number,
            "country": country,
            "region_code": region_code,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dns_resolve(hostname: str) -> str | None:
        try:
            return socket.gethostbyname(hostname)
        except (socket.gaierror, OSError):
            return None

    @staticmethod
    def _extract_domain(url: str) -> str | None:
        cleaned = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
        host = cleaned.split("/", 1)[0].split(":", 1)[0].lower()
        return host if "." in host else None

    async def mac_oui_trace(self, mac: str) -> dict[str, Any] | None:
        """Full Plan MAC address vendor/country trace."""
        from services.full_plan_research import mac_oui_lookup

        return mac_oui_lookup(mac)

    @staticmethod
    def _correlate(signals: list[dict[str, Any]]) -> dict[str, Any]:
        """Pick the most trustworthy location estimate from collected signals."""
        if not signals:
            return {
                "country": "Unknown",
                "city": None,
                "confidence": "none",
                "method": "no_signals",
            }

        countries: dict[str, int] = {}
        best_city: str | None = None
        best_lat: float | None = None
        best_lon: float | None = None
        best_source: str = "unknown"
        has_vpn_flag = False

        for sig in signals:
            c = sig.get("country")
            if not c:
                continue
            countries[c] = countries.get(c, 0) + 1

            if sig.get("is_proxy_or_vpn"):
                has_vpn_flag = True

            if sig.get("method") == "subdomain_bypass":
                best_city = sig.get("city")
                best_lat = sig.get("lat")
                best_lon = sig.get("lon")
                best_source = "subdomain_bypass"

        if not countries:
            return {
                "country": "Unknown",
                "city": None,
                "confidence": "none",
                "method": "no_geo_signals",
            }

        top_country = max(countries, key=lambda k: countries[k])

        if best_source != "subdomain_bypass":
            for sig in signals:
                if sig.get("country") == top_country and sig.get("city"):
                    best_city = sig.get("city")
                    best_lat = sig.get("lat")
                    best_lon = sig.get("lon")
                    best_source = sig.get("source", "ip_geolocation")
                    break

        agreement = countries[top_country]
        total = sum(countries.values())
        if agreement == total and total >= 2:
            confidence = "high"
        elif agreement > total / 2:
            confidence = "medium"
        else:
            confidence = "low"

        return {
            "country": top_country,
            "city": best_city,
            "lat": best_lat,
            "lon": best_lon,
            "confidence": confidence,
            "method": best_source,
            "vpn_detected": has_vpn_flag,
            "signals_count": total,
        }
