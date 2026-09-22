"""
TryScope - CSV export
Flattens the report into a single-row CSV.
"""
import csv
from pathlib import Path

from .. import logger


FIELDS = [
    "ip", "country", "country_code", "city", "region", "postal",
    "lat", "lon", "timezone", "isp", "org", "asn", "reverse_dns",
    "abuse_score", "abuse_reports", "vt_malicious", "vt_total",
    "greynoise", "blacklists_listed", "blacklists_checked",
    "is_proxy", "is_hosting",
    "favicon_hash", "jarm_prefix",
    "cert_siblings", "reverse_ip_domains", "bgp_cidrs",
    "cluster_ips", "cluster_domains",
    "score", "level", "verdict", "confidence",
]


def _flatten(data: dict) -> dict:
    country = data.get("country", {}) or {}
    abuse = data.get("abuseipdb", {}) or {}
    vt = data.get("virustotal", {}) or {}
    gn = data.get("greynoise", {}) or {}
    bl = data.get("blacklists", {}) or {}
    fav = data.get("favicon", {}) or {}
    jarm_data = data.get("jarm", {}) or {}
    cert_data = data.get("cert", {}) or {}
    dns_hist = data.get("dns_history", {}) or {}
    bgp = data.get("bgp", {}) or {}
    cluster = data.get("cluster", {}) or {}
    verdict = data.get("verdict", {}) or {}

    return {
        "ip":                data.get("ip", ""),
        "country":           country.get("country", ""),
        "country_code":      country.get("country_code", ""),
        "city":              country.get("city", ""),
        "region":            country.get("region", ""),
        "postal":            country.get("postal", ""),
        "lat":               country.get("lat", 0),
        "lon":               country.get("lon", 0),
        "timezone":          country.get("timezone", ""),
        "isp":               country.get("isp", ""),
        "org":               country.get("org", ""),
        "asn":               country.get("asn", ""),
        "reverse_dns":       country.get("reverse_dns", ""),
        "abuse_score":       abuse.get("score", 0),
        "abuse_reports":     abuse.get("total_reports", 0),
        "vt_malicious":      vt.get("malicious", 0),
        "vt_total":          vt.get("total_engines", 0),
        "greynoise":         gn.get("classification", ""),
        "blacklists_listed": bl.get("total_listed", 0),
        "blacklists_checked": bl.get("total_checked", 0),
        "is_proxy":          country.get("is_proxy", False),
        "is_hosting":        country.get("is_hosting", False),
        "favicon_hash":      fav.get("hash", ""),
        "jarm_prefix":       jarm_data.get("jarm", "")[:16],
        "cert_siblings":     cert_data.get("total_found", 0),
        "reverse_ip_domains": dns_hist.get("total_domains", 0),
        "bgp_cidrs":         bgp.get("total_cidrs", 0),
        "cluster_ips":       cluster.get("stats", {}).get("total_ips", 0),
        "cluster_domains":   cluster.get("stats", {}).get("total_domains", 0),
        "score":             verdict.get("score", 0),
        "level":             verdict.get("level", ""),
        "verdict":           verdict.get("verdict", ""),
        "confidence":        verdict.get("confidence", ""),
    }


def save(data: dict, path: str) -> str:
    try:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerow(_flatten(data))
        logger.ok(f"CSV saved: {out}")
        return str(out)
    except Exception as e:
        logger.warn(f"CSV save failed: {e}")
        return ""
