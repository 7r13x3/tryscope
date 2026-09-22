"""
TryScope - Shodan InternetDB source
Free, no API key, no rate limit.
Provides: open ports, hostnames, CVEs, tags.
"""
import httpx

from .. import logger


BASE = "https://internetdb.shodan.io"


async def fetch(ip: str, timeout: int = 10) -> dict:
    """Fetch open ports + CVEs + tags from Shodan InternetDB."""
    url = f"{BASE}/{ip}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)

            if r.status_code == 404:
                return {
                    "ports": [],
                    "hostnames": [],
                    "cpes": [],
                    "vulns": [],
                    "tags": [],
                }

            if r.status_code != 200:
                logger.warn(f"InternetDB returned {r.status_code}")
                return {}

            data = r.json()

            return {
                "ports":     data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "cpes":      data.get("cpes", []),
                "vulns":     data.get("vulns", []),
                "tags":      data.get("tags", []),
            }
    except Exception as e:
        logger.warn(f"InternetDB failed: {e}")
        return {}
