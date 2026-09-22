"""
TryScope - Aggregation
Runs every data source + enrichment + pivot concurrently and merges
everything into one unified result object.
"""
import asyncio
from typing import Any

from .. import logger
from ..sources import (
    ip_api, ipwhois, rdap, internetdb,
    abuseipdb, virustotal, greynoise,
)
from ..blacklist import dnsbl
from ..enrichment import country as country_enrich
from ..enrichment import sun_time, map_link
from ..pivot import favicon, jarm, cert, dns_history, bgp
from . import scoring, verdict


async def aggregate(ip: str, cfg) -> dict:
    """
    Run the full pipeline: sources + enrichment + pivot + analysis.
    Returns a single dict with all fields.
    """
    logger.info(f"Aggregating data for {ip}")

    tasks = {}

    # --- Core sources ---
    if cfg.sources.ip_api:
        tasks["ip_api"] = asyncio.create_task(
            ip_api.fetch(ip, cfg.core.timeout_seconds)
        )
    if cfg.sources.internetdb:
        tasks["internetdb"] = asyncio.create_task(
            internetdb.fetch(ip, cfg.core.timeout_seconds)
        )
    if cfg.sources.rdap:
        tasks["rdap"] = asyncio.create_task(
            rdap.fetch(ip, cfg.core.timeout_seconds)
        )

    # --- Reputation ---
    if cfg.sources.abuseipdb_key:
        tasks["abuseipdb"] = asyncio.create_task(
            abuseipdb.fetch(ip, cfg.sources.abuseipdb_key,
                            cfg.core.timeout_seconds)
        )
    if cfg.sources.virustotal_key:
        tasks["virustotal"] = asyncio.create_task(
            virustotal.fetch(ip, cfg.sources.virustotal_key,
                             cfg.core.timeout_seconds)
        )
    if cfg.sources.greynoise_key:
        tasks["greynoise"] = asyncio.create_task(
            greynoise.fetch(ip, cfg.sources.greynoise_key,
                            cfg.core.timeout_seconds)
        )

    # --- Blacklists ---
    tasks["blacklists"] = asyncio.create_task(
        dnsbl.check_summary(ip, tier_max=2)
    )

    # --- Country enrichment ---
    tasks["country"] = asyncio.create_task(
        country_enrich.enrich(ip, cfg)
    )

    # --- Pivots ---
    if cfg.pivot.enabled:
        if cfg.pivot.favicon_pivot:
            tasks["favicon"] = asyncio.create_task(
                favicon.pivot(ip, cfg.core.timeout_seconds)
            )
        if cfg.pivot.bgp_pivot:
            tasks["bgp"] = asyncio.create_task(
                bgp.pivot(ip, cfg.core.timeout_seconds)
            )
        if cfg.pivot.dns_pivot:
            tasks["dns_history"] = asyncio.create_task(
                dns_history.pivot(ip, cfg.core.timeout_seconds)
            )

    # --- Wait for all tasks ---
    results = {}
    for name, task in tasks.items():
        try:
            results[name] = await task
        except Exception as e:
            logger.warn(f"{name} failed: {e}")
            results[name] = {}

    # --- Add JARM (sync, run in executor) ---
    if cfg.pivot.enabled and cfg.pivot.jarm_pivot:
        try:
            loop = asyncio.get_event_loop()
            results["jarm"] = await asyncio.wait_for(
                loop.run_in_executor(None, jarm.pivot, ip),
                timeout=30,
            )
        except Exception as e:
            logger.warn(f"JARM failed: {e}")
            results["jarm"] = {}

    # --- Derive extra fields from country ---
    if results.get("country"):
        c = results["country"]
        sun = sun_time.compute_local_time(
            c.get("timezone", ""), c.get("timezone_utc", "")
        )
        c["local_time"]    = sun.get("local_time", "")
        c["is_evening"]    = sun.get("is_evening", False)
        c["is_night"]      = sun.get("is_night", False)
        c["is_business"]   = sun.get("is_business", False)
        c["day_phase"]     = sun_time.day_phase(
            sun.get("is_night", False),
            sun.get("is_evening", False),
            sun.get("is_business", False),
        )
        maps = map_link.all_links(c.get("lat", 0.0), c.get("lon", 0.0))
        c["google_maps_url"] = maps["google_maps"]
        c["osm_url"]         = maps["osm"]
        c["osm_static_url"]  = maps["osm_static"]

    # --- Cert pivot (needs hostnames from country/reverse_dns) ---
    if cfg.pivot.enabled and cfg.pivot.cert_pivot:
        hosts = []
        if results.get("country", {}).get("reverse_dns"):
            hosts.append(results["country"]["reverse_dns"])
        if results.get("dns_history", {}).get("reverse_ip_domains"):
            hosts += results["dns_history"]["reverse_ip_domains"][:3]
        if hosts:
            try:
                results["cert"] = await cert.pivot(
                    ip, hosts, cfg.core.timeout_seconds
                )
            except Exception as e:
                logger.warn(f"Cert pivot failed: {e}")
                results["cert"] = {}

    # --- Analysis ---
    score_data = scoring.compute(results)
    verdict_data = verdict.compute(score_data, results)

    results["ip"] = ip
    results["scoring"] = score_data
    results["verdict"] = verdict_data

    return results
