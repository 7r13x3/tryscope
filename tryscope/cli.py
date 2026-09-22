"""
TryScope - CLI commands
"""
import argparse
import sys
import asyncio
import time
from pathlib import Path

from .config import load
from .cache import Cache
from .utils import is_valid_ip
from .analysis import aggregate, cluster
from .report import console as console_report
from .report import json_out, csv_out, html as html_report
from .report import graph as graph_report
from . import logger
from . import __version__


CONFIG_PATH = "configs/example.toml"


def _run(ip, cfg):
    data = asyncio.run(aggregate.aggregate(ip, cfg))
    data["cluster"] = cluster.build(data)
    return data


def cmd_lookup(args):
    if not is_valid_ip(args.ip):
        logger.error(f"Invalid IP: {args.ip}")
        sys.exit(1)

    cfg = load(args.config)
    data = _run(args.ip, cfg)
    console_report.print_report(data)

    if args.output:
        out = args.output
        ts = time.strftime("%Y%m%d_%H%M%S")
        json_out.save(data, f"{out}_{ts}.json")
        html_report.generate(data, f"{out}_{ts}.html")


def cmd_pivot(args):
    if not is_valid_ip(args.ip):
        logger.error(f"Invalid IP: {args.ip}")
        sys.exit(1)

    cfg = load(args.config)
    data = _run(args.ip, cfg)
    c = cluster.build(data)

    logger.report_header(f"Pivot - {args.ip}")
    s = c.get("stats", {})
    logger.console.print(f"    IPs:      {s.get('total_ips', 0)}")
    logger.console.print(f"    Domains:  {s.get('total_domains', 0)}")
    logger.console.print(f"    ASNs:     {s.get('total_asns', 0)}")

    graph_report.render(c, f"reports/pivot_{args.ip}.png")


def cmd_batch(args):
    cfg = load(args.config)
    cache = Cache(cfg.core.cache_db, cfg.core.cache_ttl_hours)

    with open(args.file) as f:
        ips = [l.strip() for l in f if l.strip() and is_valid_ip(l.strip())]

    logger.info(f"Batch lookup: {len(ips)} IPs")
    results = []
    for i, ip in enumerate(ips, 1):
        logger.console.print(f"  [{i}/{len(ips)}] {ip}")
        data = _run(ip, cfg)
        v = data.get("verdict", {})
        results.append({
            "ip": ip,
            "score": v.get("score", 0),
            "level": v.get("level", "?"),
        })
        cache.set(ip, data)

    rows = [[r["ip"], str(r["score"]), r["level"]] for r in results]
    logger.table("Batch Results", ["IP", "Score", "Level"], rows)


def cmd_check(args):
    try:
        cfg = load(args.config)
    except Exception as e:
        logger.error(f"Config error: {e}")
        sys.exit(1)

    logger.panel("Config OK", (
        f"Timeout:       {cfg.core.timeout_seconds}s\n"
        f"Workers:       {cfg.core.max_workers}\n"
        f"Cache TTL:     {cfg.core.cache_ttl_hours}h\n"
        f"Pivot enabled: {cfg.pivot.enabled}\n"
        f"Pivot depth:   {cfg.pivot.depth}\n"
    ))


def cmd_gui(args):
    from .menu import run
    run(args.config)


def main():
    parser = argparse.ArgumentParser(
        prog="tryscope",
        description="TryScope - IP Intelligence",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("lookup", help="Full analysis of one IP")
    p.add_argument("ip")
    p.add_argument("--config", "-c", default=CONFIG_PATH)
    p.add_argument("--output", "-o")
    p.set_defaults(func=cmd_lookup)

    p = sub.add_parser("pivot", help="Pivot from an IP")
    p.add_argument("ip")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--config", "-c", default=CONFIG_PATH)
    p.set_defaults(func=cmd_pivot)

    p = sub.add_parser("batch", help="Batch lookup from file")
    p.add_argument("--file", "-f", required=True)
    p.add_argument("--config", "-c", default=CONFIG_PATH)
    p.set_defaults(func=cmd_batch)

    p = sub.add_parser("check", help="Validate config")
    p.add_argument("--config", "-c", default=CONFIG_PATH)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("gui", help="Interactive menu")
    p.add_argument("--config", "-c", default=CONFIG_PATH)
    p.set_defaults(func=cmd_gui)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
