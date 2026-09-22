"""
TryScope - ip-api.com source
Free, no API key. 45 requests/minute.
Provides: geo, ISP, ASN, timezone, postal code, lat/lon.
"""
import httpx

from .. import logger


BASE = "http://ip-api.com/json"


async def fetch(ip: str, timeout: int = 10) -> dict:
    """Fetch geolocation + network info from ip-api.com."""
    url = f"{BASE}/{ip}"
    params = {
        "fields": (
            "status,message,country,countryCode,region,regionName,"
            "city,zip,lat,lon,timezone,isp,org,as,asname,"
            "reverse,mobile,proxy,hosting,query"
        )
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url, params=params)
            if r.status_code != 200:
                logger.warn(f"ip-api.com returned {r.status_code}")
                return {}

            data = r.json()
            if data.get("status") != "success":
                msg = data.get("message", "unknown error")
                logger.warn(f"ip-api.com: {msg}")
                return {}

            return {
                "country":      data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "region":       data.get("regionName", ""),
                "city":         data.get("city", ""),
                "postal":       data.get("zip", ""),
                "lat":          data.get("lat", 0.0),
                "lon":          data.get("lon", 0.0),
                "timezone":     data.get("timezone", ""),
                "isp":          data.get("isp", ""),
                "org":          data.get("org", ""),
                "asn_full":     data.get("as", ""),
                "asn_name":     data.get("asname", ""),
                "reverse_dns":  data.get("reverse", ""),
                "mobile":       data.get("mobile", False),
                "proxy":        data.get("proxy", False),
                "hosting":      data.get("hosting", False),
            }
    except Exception as e:
        logger.warn(f"ip-api.com failed: {e}")
        return {}
