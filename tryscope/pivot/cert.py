"""
TryScope - Certificate SAN pivot
Queries crt.sh (Certificate Transparency logs) for every cert issued
for sibling domains. Free, no API key.
"""
import asyncio
from typing import List

import httpx

from .. import logger


CRTSH = "https://crt.sh/"


async def search_by_domain(domain: str, timeout: int = 20) -> List[str]:
    """Query crt.sh for all subdomains of a domain."""
    url = f"{CRTSH}?q=%25.{domain}&output=json"
    names = set()

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return []

            data = r.json()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if name and "@" not in name:
                        names.add(name)
    except Exception as e:
        logger.warn(f"crt.sh failed for {domain}: {e}")

    return sorted(names)


async def pivot(ip: str, hostnames: List[str], timeout: int = 20) -> dict:
    """
    Given a list of hostnames resolved to this IP, look up sibling
    domains via certificate transparency logs.
    """
    if not hostnames:
        return {}

    all_siblings = set()
    domains_checked = 0

    for host in hostnames[:3]:
        # get root domain (last 2 labels)
        parts = host.split(".")
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
        else:
            continue

        domains_checked += 1
        siblings = await search_by_domain(root, timeout)
        for s in siblings:
            if s != host:
                all_siblings.add(s)

    siblings_list = sorted(all_siblings)[:50]

    if siblings_list:
        logger.ok(f"Cert SAN pivot: {len(siblings_list)} sibling domains")

    return {
        "domains_checked":  domains_checked,
        "sibling_domains":  siblings_list,
        "total_found":      len(siblings_list),
    }
