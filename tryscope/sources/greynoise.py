"""
TryScope - GreyNoise source
Free API key: https://viz.greynoise.io/signup
Free tier: 50 requests/day.
Provides: scanner classification, actor tags, RIOT.
"""
import httpx

from .. import logger


BASE = "https://api.greynoise.io/v3/community"


async def fetch(ip: str, api_key: str = "", timeout: int = 10) -> dict:
    """
    Fetch GreyNoise community data.
    Works without a key but rate limited to 25/day per IP.
    """
    url = f"{BASE}/{ip}"
    headers = {}
    if api_key:
        headers["key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url, headers=headers)

            if r.status_code == 404:
                return {
                    "noise":     False,
                    "riot":      False,
                    "message":   "not observed",
                }
            if r.status_code == 429:
                logger.warn("GreyNoise: rate limit reached")
                return {}
            if r.status_code != 200:
                logger.warn(f"GreyNoise returned {r.status_code}")
                return {}

            data = r.json()

            return {
                "noise":         data.get("noise", False),
                "riot":          data.get("riot", False),
                "classification": data.get("classification", "unknown"),
                "name":          data.get("name", ""),
                "link":          data.get("link", ""),
                "last_seen":     data.get("last_seen", ""),
                "message":       data.get("message", ""),
            }
    except Exception as e:
        logger.warn(f"GreyNoise failed: {e}")
        return {}
