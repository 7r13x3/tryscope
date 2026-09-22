"""
TryScope - REST Countries source
Free, no API key, no rate limit.
Provides: currency, calling code, borders, population, languages.
"""
import httpx

from .. import logger


BASE = "https://restcountries.com/v3.1/alpha"


async def fetch(country_code: str, timeout: int = 10) -> dict:
    """Fetch country metadata from restcountries.com."""
    if not country_code:
        return {}

    url = f"{BASE}/{country_code}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            if r.status_code != 200:
                logger.warn(f"REST Countries returned {r.status_code}")
                return {}

            data = r.json()
            if isinstance(data, list):
                if not data:
                    return {}
                data = data[0]

            # currencies
            currencies = data.get("currencies", {}) or {}
            currency_code = ""
            currency_name = ""
            currency_symbol = ""
            for code, info in currencies.items():
                currency_code = code
                currency_name = info.get("name", "")
                currency_symbol = info.get("symbol", "")
                break

            # calling code
            idd = data.get("idd", {}) or {}
            root = idd.get("root", "")
            suffixes = idd.get("suffixes", []) or []
            calling_code = root + (suffixes[0] if suffixes else "")

            # languages
            languages = list((data.get("languages", {}) or {}).values())

            return {
                "official_name": data.get("name", {}).get("official", ""),
                "common_name":   data.get("name", {}).get("common", ""),
                "capital":       (data.get("capital") or [""])[0],
                "region":        data.get("region", ""),
                "subregion":     data.get("subregion", ""),
                "population":    data.get("population", 0),
                "languages":     languages,
                "currency_code":   currency_code,
                "currency_name":   currency_name,
                "currency_symbol": currency_symbol,
                "calling_code":    calling_code,
                "borders":         data.get("borders", []),
                "flag_emoji":      data.get("flag", ""),
                "timezones":       data.get("timezones", []),
            }
    except Exception as e:
        logger.warn(f"REST Countries failed: {e}")
        return {}
