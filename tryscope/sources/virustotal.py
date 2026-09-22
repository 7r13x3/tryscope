"""
TryScope - VirusTotal source
Requires free API key: https://www.virustotal.com/gui/join-us
Free tier: 4 requests/minute, 500/day.
Provides: engine detections, malware families, reputation.
"""
import httpx

from .. import logger


BASE = "https://www.virustotal.com/api/v3/ip_addresses"


async def fetch(ip: str, api_key: str, timeout: int = 15) -> dict:
    """Fetch VirusTotal reports for an IP."""
    if not api_key:
        return {}

    url = f"{BASE}/{ip}"
    headers = {"x-apikey": api_key}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url, headers=headers)

            if r.status_code == 401:
                logger.warn("VirusTotal: invalid API key")
                return {}
            if r.status_code == 429:
                logger.warn("VirusTotal: rate limit reached")
                return {}
            if r.status_code == 404:
                return {}
            if r.status_code != 200:
                logger.warn(f"VirusTotal returned {r.status_code}")
                return {}

            data = r.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})

            families = []
            engines_flagged = []
            for engine, result in results.items():
                if result.get("category") == "malicious":
                    engines_flagged.append(engine)
                    family = result.get("result", "")
                    if family and family not in families:
                        families.append(family)

            return {
                "malicious":     stats.get("malicious", 0),
                "suspicious":    stats.get("suspicious", 0),
                "harmless":      stats.get("harmless", 0),
                "undetected":    stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "engines_flagged": engines_flagged[:10],
                "malware_families": families[:5],
                "reputation":    attrs.get("reputation", 0),
                "country":       attrs.get("country", ""),
                "asn":           attrs.get("asn", 0),
                "as_owner":      attrs.get("as_owner", ""),
                "network":       attrs.get("network", ""),
                "tags":          attrs.get("tags", []),
            }
    except Exception as e:
        logger.warn(f"VirusTotal failed: {e}")
        return {}
