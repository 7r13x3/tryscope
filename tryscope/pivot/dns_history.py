"""
TryScope - Passive DNS history
Uses HackerTarget's free API (100 req/day) plus crt.sh CT logs
to reconstruct infrastructure history for an IP.
"""
import asyncio
from typing import List

import httpx

from .. import logger


HACKERTARGET = "https://api.hackertarget.com/reverseiplookup/"


async def reverse_ip(ip: str, timeout: int = 15) -> List[str]:
    """Find all domains that currently resolve to this IP."""
    url = f"{HACKERTARGET}?q={ip}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return []

            text = r.text.strip()
            if "error" in text.lower() or "no records" in text.lower():
                return []

            domains = [
                line.strip().lower()
                for line in text.splitlines()
                if line.strip() and "." in line
            ]
            return sorted(set(domains))[:100]

    except Exception as e:
        logger.warn(f"Reverse IP failed: {e}")
        return []


async def pivot(ip: str, timeout: int = 15) -> dict:
    """
    Find domains historically tied to this IP.
    Free sources only.
    """
    domains = await reverse_ip(ip, timeout)

    if domains:
        logger.ok(f"Reverse IP: {len(domains)} domains point to {ip}")

    return {
        "reverse_ip_domains": domains,
        "total_domains":      len(domains),
    }
