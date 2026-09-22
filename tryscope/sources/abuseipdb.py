"""
TryScope - AbuseIPDB source
Requires free API key: https://www.abuseipdb.com/register
Free tier: 1,000 checks/day.
Provides: abuse confidence score, report count, categories.
"""
import httpx

from .. import logger


BASE = "https://api.abuseipdb.com/api/v2/check"

CATEGORIES = {
    1:  "DNS Compromise",
    2:  "DNS Poisoning",
    3:  "Fraud Orders",
    4:  "DDoS Attack",
    5:  "FTP Brute-Force",
    6:  "Ping of Death",
    7:  "Phishing",
    8:  "Fraud VoIP",
    9:  "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


async def fetch(ip: str, api_key: str,
                timeout: int = 10, max_age_days: int = 90) -> dict:
    """Fetch abuse report data from AbuseIPDB."""
    if not api_key:
        return {}

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": max_age_days,
        "verbose": "true",
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(BASE, headers=headers, params=params)

            if r.status_code == 401:
                logger.warn("AbuseIPDB: invalid API key")
                return {}
            if r.status_code == 429:
                logger.warn("AbuseIPDB: rate limit reached")
                return {}
            if r.status_code != 200:
                logger.warn(f"AbuseIPDB returned {r.status_code}")
                return {}

            data = r.json().get("data", {})

            cats = []
            for report in data.get("reports", [])[:5]:
                for c in report.get("categories", []):
                    name = CATEGORIES.get(c, f"cat-{c}")
                    if name not in cats:
                        cats.append(name)

            return {
                "score":            data.get("abuseConfidenceScore", 0),
                "total_reports":    data.get("totalReports", 0),
                "distinct_users":   data.get("numDistinctUsers", 0),
                "last_reported":    data.get("lastReportedAt", ""),
                "categories":       cats,
                "whitelisted":      data.get("isWhitelisted", False),
                "usage_type":       data.get("usageType", ""),
                "domain":           data.get("domain", ""),
                "country_code":     data.get("countryCode", ""),
            }
    except Exception as e:
        logger.warn(f"AbuseIPDB failed: {e}")
        return {}
