"""
TryScope - Favicon pivot
Downloads the favicon from a host, computes its MMH3 hash (Shodan-style),
and (optionally) looks it up on Censys / FOFA.

The favicon hash is a "fingerprint" of the web app. Servers sharing
the same favicon often belong to the same operator.
"""
import base64
import hashlib

import httpx

from .. import logger


def mmh3_hash(data: bytes) -> int:
    """
    Compute Shodan-style favicon hash.
    Format: mmh3(base64_with_newlines(data))
    """
    try:
        import mmh3
        encoded = base64.encodebytes(data)
        return mmh3.hash(encoded)
    except ImportError:
        return _pure_mmh3(base64.encodebytes(data))


def _pure_mmh3(data: bytes) -> int:
    """Pure Python MurmurHash3 (32-bit x86 variant)."""
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = 0
    rounded_end = length & 0xfffffffc

    for i in range(0, rounded_end, 4):
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) \
             | ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff

    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded_end + 2] & 0xff) << 16
    if tail in (2, 3):
        k1 |= (data[rounded_end + 1] & 0xff) << 8
    if tail in (1, 2, 3):
        k1 |= data[rounded_end] & 0xff
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16

    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


async def fetch_favicon(ip: str, timeout: int = 10) -> bytes:
    """Try to download /favicon.ico from the IP over HTTPS then HTTP."""
    for scheme in ("https", "http"):
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
            ) as client:
                r = await client.get(f"{scheme}://{ip}/favicon.ico")
                if r.status_code == 200 and r.content and len(r.content) > 8:
                    return r.content
        except Exception:
            continue
    return b""


async def pivot(ip: str, timeout: int = 10) -> dict:
    """
    Compute the favicon hash for an IP.
    Returns {hash, url, size, shodan_query, censys_query}.
    """
    data = await fetch_favicon(ip, timeout)
    if not data:
        return {}

    h = mmh3_hash(data)
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()[:16]

    logger.ok(f"Favicon hash: mmh3:{h} ({len(data)} bytes)")

    return {
        "hash":          h,
        "md5":           md5,
        "sha256_prefix": sha256,
        "size":          len(data),
        "shodan_query":  f"http.favicon.hash:{h}",
        "censys_query":  f"services.http.response.favicons.md5_hash: {md5}",
        "fofa_query":    f'icon_hash="{h}"',
        "zoomeye_query": f'iconhash:"{md5}"',
        "pivot_urls": {
            "shodan":  f"https://www.shodan.io/search?query=http.favicon.hash%3A{h}",
            "censys":  f"https://search.censys.io/search?resource=hosts&q=services.http.response.favicons.md5_hash%3A{md5}",
            "fofa":    f'https://fofa.info/result?qbase64=icon_hash%3D%22{h}%22',
            "zoomeye": f'https://www.zoomeye.org/searchResult?q=iconhash%3A%22{md5}%22',
        },
    }
