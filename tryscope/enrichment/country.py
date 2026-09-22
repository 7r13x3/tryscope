"""
TryScope - Country enrichment
Merges geo data from ip-api, ipwho.is, and REST Countries into one object.
"""
from .. import logger
from ..sources import ip_api, ipwhois, restcountries


async def enrich(ip: str, cfg) -> dict:
    """
    Combine geo + country metadata from multiple sources.
    Priority: ipwho.is > ip-api > restcountries for country metadata.
    """
    result = {
        "country":         "",
        "country_code":    "",
        "country_code3":   "",
        "city":            "",
        "region":          "",
        "postal":          "",
        "lat":             0.0,
        "lon":             0.0,
        "continent":       "",
        "timezone":        "",
        "timezone_utc":    "",
        "local_time":      "",
        "is_evening":      False,
        "sunrise":         "",
        "sunset":          "",
        "capital":         "",
        "population":      0,
        "languages":       [],
        "currency_code":   "",
        "currency_name":   "",
        "currency_symbol": "",
        "calling_code":    "",
        "flag_emoji":      "",
        "borders":         [],
        "isp":             "",
        "org":             "",
        "asn":             "",
        "asn_name":        "",
        "reverse_dns":     "",
        "is_proxy":        False,
        "is_hosting":      False,
        "is_mobile":       False,
    }

    # --- ip-api ---
    if cfg.sources.ip_api:
        data = await ip_api.fetch(ip, cfg.core.timeout_seconds)
        if data:
            result["country"]      = data.get("country", "")
            result["country_code"] = data.get("country_code", "")
            result["region"]       = data.get("region", "")
            result["city"]         = data.get("city", "")
            result["postal"]       = data.get("postal", "")
            result["lat"]          = data.get("lat", 0.0)
            result["lon"]          = data.get("lon", 0.0)
            result["timezone"]     = data.get("timezone", "")
            result["isp"]          = data.get("isp", "")
            result["org"]          = data.get("org", "")
            result["asn_name"]     = data.get("asn_name", "")
            result["reverse_dns"]  = data.get("reverse_dns", "")
            result["is_proxy"]     = data.get("proxy", False)
            result["is_hosting"]   = data.get("hosting", False)
            result["is_mobile"]    = data.get("mobile", False)
            asn_full = data.get("asn_full", "")
            if asn_full:
                result["asn"] = asn_full.split(" ")[0]

    # --- ipwho.is ---
    if cfg.sources.ipwhois:
        data = await ipwhois.fetch(ip, cfg.core.timeout_seconds)
        if data:
            # ipwho.is as fallback / primary for some fields
            if not result["country"]:
                result["country"] = data.get("country", "")
            if not result["country_code"]:
                result["country_code"] = data.get("country_code", "")
            if not result["city"]:
                result["city"] = data.get("city", "")
            if not result["region"]:
                result["region"] = data.get("region", "")
            if not result["postal"]:
                result["postal"] = data.get("postal", "")
            if not result["timezone"]:
                result["timezone"] = data.get("timezone_id", "")
            result["continent"]       = data.get("continent", "")
            result["timezone_utc"]    = data.get("timezone_utc", "")
            result["capital"]         = data.get("capital", "")
            result["calling_code"]    = data.get("calling_code", "")
            result["currency_code"]   = data.get("currency_code", "")
            result["currency_name"]   = data.get("currency_name", "")
            result["currency_symbol"] = data.get("currency_symbol", "")
            result["flag_emoji"]      = data.get("flag_emoji", "")
            if not result["isp"]:
                result["isp"] = data.get("isp", "")
            if not result["org"]:
                result["org"] = data.get("org", "")

    # --- REST Countries ---
    if cfg.sources.restcountries and result["country_code"]:
        data = await restcountries.fetch(
            result["country_code"], cfg.core.timeout_seconds
        )
        if data:
            if not result["capital"]:
                result["capital"] = data.get("capital", "")
            if not result["calling_code"]:
                result["calling_code"] = data.get("calling_code", "")
            if not result["currency_code"]:
                result["currency_code"] = data.get("currency_code", "")
            if not result["currency_name"]:
                result["currency_name"] = data.get("currency_name", "")
            if not result["currency_symbol"]:
                result["currency_symbol"] = data.get("currency_symbol", "")
            if not result["flag_emoji"]:
                result["flag_emoji"] = data.get("flag_emoji", "")
            result["country_code3"] = result["country_code"] + "X"
            result["population"]    = data.get("population", 0)
            result["languages"]     = data.get("languages", [])
            result["borders"]       = data.get("borders", [])
            if not result["continent"]:
                result["continent"] = data.get("region", "")

    return result
