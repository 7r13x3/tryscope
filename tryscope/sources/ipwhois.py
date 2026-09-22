"""
TryScope - ipwho.is source
Free, no API key, no rate limit (fair use).
Provides: geo, ASN, continent, currency, calling code, flag.
"""
import httpx

from .. import logger


BASE = "https://ipwho.is"


async def fetch(ip: str, timeout: int = 10) -> dict:
    """Fetch geolocation + country details from ipwho.is."""
    url = f"{BASE}/{ip}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            if r.status_code != 200:
                logger.warn(f"ipwho.is returned {r.status_code}")
                return {}

            data = r.json()
            if not data.get("success", False):
                logger.warn(f"ipwho.is: {data.get('message', 'error')}")
                return {}

            connection = data.get("connection", {}) or {}
            timezone = data.get("timezone", {}) or {}
            currency = data.get("currency", {}) or {}

            return {
                "country":          data.get("country", ""),
                "country_code":     data.get("country_code", ""),
                "city":             data.get("city", ""),
                "region":           data.get("region", ""),
                "postal":           data.get("postal", ""),
                "lat":              data.get("latitude", 0.0),
                "lon":              data.get("longitude", 0.0),
                "continent":        data.get("continent", ""),
                "continent_code":   data.get("continent_code", ""),
                "capital":          data.get("capital", ""),
                "calling_code":     data.get("calling_code", ""),
                "currency_code":    currency.get("code", ""),
                "currency_name":    currency.get("name", ""),
                "currency_symbol":  currency.get("symbol", ""),
                "flag_emoji":       data.get("flag", {}).get("emoji", ""),
                "timezone_id":      timezone.get("id", ""),
                "timezone_utc":     timezone.get("utc", ""),
                "isp":              connection.get("isp", ""),
                "org":              connection.get("org", ""),
                "asn":              connection.get("asn", ""),
                "domain":           connection.get("domain", ""),
            }
    except Exception as e:
        logger.warn(f"ipwho.is failed: {e}")
        return {}
