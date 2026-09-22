"""
TryScope - RDAP source
Free, no API key, no rate limit.
Provides: WHOIS-style registration data for the IP's block.
"""
import httpx

from .. import logger


BASE = "https://rdap.org/ip"


async def fetch(ip: str, timeout: int = 10) -> dict:
    """Fetch RDAP data for an IP address."""
    url = f"{BASE}/{ip}"

    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True
        ) as client:
            r = await client.get(url)
            if r.status_code != 200:
                logger.warn(f"RDAP returned {r.status_code}")
                return {}

            data = r.json()

            result = {
                "handle":   data.get("handle", ""),
                "name":     data.get("name", ""),
                "country":  data.get("country", ""),
                "type":     data.get("type", ""),
                "start_address": data.get("startAddress", ""),
                "end_address":   data.get("endAddress", ""),
                "parent_handle": data.get("parentHandle", ""),
                "status":   data.get("status", []),
            }

            # extract org name from entities
            for entity in data.get("entities", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item and item[0] == "fn":
                            result["organization"] = item[3]
                            break
                if "abuse" in entity.get("roles", []):
                    for item in vcard[1] if len(vcard) > 1 else []:
                        if item and item[0] == "email":
                            result["abuse_email"] = item[3]

            return result
    except Exception as e:
        logger.warn(f"RDAP failed: {e}")
        return {}
