"""
TryScope - BGP pivot
Given an IP, find its ASN and all CIDR ranges the ASN owns.
Uses BGPView (free, no API key).
"""
from typing import List

import httpx

from .. import logger


BGPVIEW = "https://api.bgpview.io"


async def ip_to_asn(ip: str, timeout: int = 15) -> dict:
    """Find which ASN owns an IP."""
    url = f"{BGPVIEW}/ip/{ip}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return {}

            data = r.json().get("data", {})
            prefixes = data.get("prefixes", [])
            if not prefixes:
                return {}

            p = prefixes[0]
            asn_info = p.get("asn", {})
            return {
                "asn":         asn_info.get("asn"),
                "name":        asn_info.get("name", ""),
                "description": asn_info.get("description", ""),
                "country":     asn_info.get("country_code", ""),
                "prefix":      p.get("prefix", ""),
            }
    except Exception as e:
        logger.warn(f"BGPView IP lookup failed: {e}")
        return {}


async def asn_to_prefixes(asn: int, timeout: int = 20) -> List[str]:
    """Get every CIDR range owned by an ASN."""
    url = f"{BGPVIEW}/asn/{asn}/prefixes"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return []

            data = r.json().get("data", {})
            ipv4 = [p.get("prefix") for p in data.get("ipv4_prefixes", [])]
            return [p for p in ipv4 if p]
    except Exception as e:
        logger.warn(f"BGPView ASN lookup failed: {e}")
        return []


async def pivot(ip: str, timeout: int = 15) -> dict:
    """
    Full BGP pivot: IP -> ASN -> all CIDRs owned by that ASN.
    """
    info = await ip_to_asn(ip, timeout)
    if not info:
        return {}

    asn = info.get("asn")
    if not asn:
        return {}

    logger.ok(f"ASN: AS{asn} - {info.get('name', '')}")

    prefixes = await asn_to_prefixes(asn, timeout)
    logger.ok(f"BGP: {len(prefixes)} CIDR ranges owned by AS{asn}")

    return {
        "asn":          asn,
        "asn_name":     info.get("name", ""),
        "description":  info.get("description", ""),
        "country":      info.get("country", ""),
        "target_prefix": info.get("prefix", ""),
        "cidr_ranges":  prefixes[:200],
        "total_cidrs":  len(prefixes),
    }
