"""
TryScope - DNSBL checker
Queries DNS-based blacklists to check if an IP is listed.
"""
import asyncio
import socket
from typing import List

import dns.resolver
import dns.reversename

from .. import logger
from ..utils import reverse_octets, is_ipv6
from .lists import DNSBL_LISTS, DNSBL_CODES


async def _query_one(zone: str, query: str,
                     timeout: int = 5) -> str:
    """Query a single DNSBL zone. Returns the response code or empty."""
    loop = asyncio.get_event_loop()

    def _do_query():
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(f"{query}.{zone}", "A")
            return str(answers[0].address)
        except (dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.resolver.Timeout,
                socket.gaierror):
            return ""
        except Exception:
            return ""

    return await loop.run_in_executor(None, _do_query)


async def check_all(ip: str, tier_max: int = 2,
                    timeout: int = 5) -> List[dict]:
    """
    Check an IP against all DNSBLs up to a given tier.
    Returns list of dicts for lists where the IP was found.
    """
    if is_ipv6(ip):
        logger.warn(f"DNSBL: skipping IPv6 address {ip}")
        return []

    query = reverse_octets(ip)
    if not query:
        return []

    results = []
    tasks = []

    for zone, name, category, tier in DNSBL_LISTS:
        if tier > tier_max:
            continue
        tasks.append((zone, name, category, tier,
                      asyncio.create_task(
                          _query_one(zone, query, timeout)
                      )))

    for zone, name, category, tier, task in tasks:
        code = await task
        if code:
            reason = DNSBL_CODES.get(code, "listed")
            results.append({
                "zone":     zone,
                "name":     name,
                "category": category,
                "tier":     tier,
                "code":     code,
                "reason":   reason,
            })

    return results


def count_lists(tier_max: int = 2) -> int:
    return len([x for x in DNSBL_LISTS if x[3] <= tier_max])


async def check_summary(ip: str, tier_max: int = 2) -> dict:
    """Return a summary dict for reporting."""
    listed = await check_all(ip, tier_max=tier_max)
    total = count_lists(tier_max)

    by_tier = {1: 0, 2: 0, 3: 0}
    for entry in listed:
        by_tier[entry["tier"]] = by_tier.get(entry["tier"], 0) + 1

    return {
        "total_checked": total,
        "total_listed":  len(listed),
        "listings":      listed,
        "by_tier":       by_tier,
    }
