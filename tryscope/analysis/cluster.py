"""
TryScope - Cluster builder
Builds an infrastructure cluster graph from pivot results.
Uses NetworkX to produce a graph object.
"""
from typing import Dict, List

from .. import logger


def build(aggregated: dict) -> dict:
    """
    Build a cluster summary from all pivot results.
    Returns {nodes, edges, total_ips, total_domains, stats}.
    """
    ip = aggregated.get("ip", "?")
    nodes = {ip: {"type": "target", "role": "target"}}
    edges = []
    all_ips = {ip}
    all_domains = set()
    all_asns = set()

    # favicon
    fav = aggregated.get("favicon", {})
    if fav.get("hash") is not None:
        all_ips.add(f"favicon:{fav['hash']}")
        edges.append((ip, f"favicon:{fav['hash']}", "favicon"))

    # jarm
    jarm_data = aggregated.get("jarm", {})
    if jarm_data.get("jarm"):
        all_ips.add(f"jarm:{jarm_data['jarm'][:16]}")
        edges.append((ip, f"jarm:{jarm_data['jarm'][:16]}", "jarm"))

    # dns history
    dns = aggregated.get("dns_history", {})
    for dom in dns.get("reverse_ip_domains", [])[:20]:
        all_domains.add(dom)
        edges.append((ip, dom, "reverse_dns"))

    # cert SAN
    cert_data = aggregated.get("cert", {})
    for dom in cert_data.get("sibling_domains", [])[:20]:
        all_domains.add(dom)
        edges.append((ip, dom, "cert_san"))

    # BGP
    bgp_data = aggregated.get("bgp", {})
    if bgp_data.get("asn"):
        asn_node = f"AS{bgp_data['asn']}"
        all_asns.add(asn_node)
        edges.append((ip, asn_node, "asn"))
        for cidr in bgp_data.get("cidr_ranges", [])[:10]:
            edges.append((asn_node, cidr, "cidr"))
            all_ips.add(cidr)

    stats = {
        "total_ips":      len(all_ips),
        "total_domains":  len(all_domains),
        "total_asns":     len(all_asns),
        "total_edges":    len(edges),
    }

    logger.ok(f"Cluster: {stats['total_ips']} IPs, "
              f"{stats['total_domains']} domains, "
              f"{stats['total_asns']} ASNs")

    return {
        "nodes": nodes,
        "edges": edges,
        "ips":   sorted(all_ips),
        "domains": sorted(all_domains),
        "asns":  sorted(all_asns),
        "stats": stats,
    }
