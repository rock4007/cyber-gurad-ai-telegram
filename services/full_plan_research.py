"""Full Plan advanced research APIs - Darkweb, Google Research, Malware/IP/MAC trace.

Gated by API key presence (Full Plan ₹499/mo).
"""

import os
from typing import Any

from config import settings

async def abuseipdb_check(ip: str, user_id: str, timeout: float = 10.0) -> dict[str, Any] | None:
    key = settings.abuseipdb_api_key
    if not key:
        return {"status": "full_plan_required", "message": "AbuseIPDB darkweb/abuse checks in Full Plan (₹499/mo). Use /plans"}
    try:
        import httpx
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": key, "User-Id": user_id}
            )
            if resp.status_code == 200:
                data = resp.json()
                abuse_conf = data['data']['abuseConfidenceScore']
                return {
                    "status": "success",
                    "ip": ip,
                    "abuse_confidence": abuse_conf,
                    "reports_count": data['data']['totalReports'],
                    "last_reported": data['data']['lastReportedAt'],
                    "is_malware_darkweb": abuse_conf > 50
                }
    except Exception:
        pass
    return None

async def google_dorking_multi_scan(target: str, user_id: str, timeout: float = 15.0) -> dict[str, Any]:
    """
    Multi-layer Google Dorking + CSE for deep scam research (Full Plan).
    Layers: Basic CSE, Advanced dorks, site-specific, filetype scans.
    """
    key = settings.google_custom_search_api_key
    if not key:
        return {"status": "full_plan_required", "message": "Google Dorking Multi-Scan in Full Plan (₹499/mo). /plans"}
    cx = os.getenv("GOOGLE_CSE_CX")
    if not cx:
        return {"status": "config_missing", "message": "Set GOOGLE_CSE_CX"}
    
    layers = []
    dorks = [
        f'"{target}" (scam OR fraud OR phishing OR malware OR "technical support")',
        f'site:reddit.com "{target}" scam OR fraud',
        f'site:twitter.com OR site:x.com "{target}" "verify account" OR otp',
        f'"{target}" filetype:pdf | filetype:doc "urgent"',
        f'inurl:telegram.me OR inurl:t.me "{target}"',
    ]
    
    for i, dork in enumerate(dorks, 1):
        try:
            import httpx
            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
                resp = await client.get(
                    "https://www.googleapis.com/customsearch/v1",
                    params={"key": key, "cx": cx, "q": dork, "num": 3}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    layers.append({
                        "layer": i,
                        "dork": dork,
                        "hits": data.get('searchInformation', {}).get('totalResults', 0),
                        "top_results": data.get('items', [])
                    })
        except Exception as e:
            layers.append({"layer": i, "dork": dork, "error": str(e)})
    
    return {
        "status": "success",
        "target": target,
        "layers": layers[:5],  # Top 5 dorks
        "total_mentions": sum(l['hits'] for l in layers if 'hits' in l),
        "multi_layer_hits": len([l for l in layers if l.get('hits', 0) > 0]),
        "scam_probability": min(100, sum(l.get('hits', 0) for l in layers) / 10)
    }

def mac_oui_lookup(mac: str) -> dict[str, Any]:
    """Static + API OUI lookup for MAC vendor/country trace."""
    try:
        import httpx
        oui = mac.upper().replace("-", ":").split(":")[:3]
        oui_str = "".join(oui)
        resp = httpx.get(f"https://api.macvendors.com/{oui_str}", timeout=5.0)
        if resp.status_code == 200:
            return {
                "mac": mac,
                "vendor": resp.text.strip(),
                "trace": "OUI matched - device manufacturer identified",
                "full_plan": True
            }
    except Exception:
        pass
    return {
        "mac": mac,
        "vendor": "Unknown",
        "trace": "No public OUI match"
    }
