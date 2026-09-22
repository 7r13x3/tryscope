"""
TryScope - Interactive Menu
Blue & white theme. ASCII-safe.
"""
import os
import sys
import time
import asyncio
from pathlib import Path

from . import logger
from .config import load
from .cache import Cache
from .utils import is_valid_ip
from .analysis import aggregate, cluster
from .report import console as console_report
from .report import json_out, csv_out, html as html_report
from .report import graph as graph_report


MENU_OPTIONS = [
    ("1",  "Full IP Analysis       (all features, one IP)"),
    ("2",  "Pivot from IP          (infrastructure hunting)"),
    ("3",  "Batch Lookup           (file with many IPs)"),
    ("4",  "My Public IP"),
    ("5",  "View Cache"),
    ("6",  "Clear Cache"),
    ("7",  "Settings"),
    ("0",  "Exit"),
]


CONFIG_PATH = "configs/example.toml"


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def show_header():
    logger.banner()
    logger.line("=", 64)


def show_status(cache: Cache):
    logger.console.print(
        f"[bright_blue]  CACHE:[/bright_blue]    "
        f"[white]{cache.count()} entries[/white]"
    )
    logger.line("=", 64)
    logger.console.print()


def ask(prompt: str) -> str:
    try:
        return input(f"  {prompt}").strip()
    except (KeyboardInterrupt, EOFError):
        return "back"


# =============================================================
#  ACTIONS
# =============================================================

def _run_aggregate(ip: str, cfg) -> dict:
    """Run the full pipeline synchronously."""
    data = asyncio.run(aggregate.aggregate(ip, cfg))
    data["cluster"] = cluster.build(data)
    return data


def _save_all(data: dict, ip: str, cfg):
    """Save every output format."""
    out_dir = Path(cfg.output.reports_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = time.strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"{ip.replace(':', '_')}_{ts}"

    json_out.save(data, str(base) + ".json")
    csv_out.save(data, str(base) + ".csv")
    html_report.generate(data, str(base) + ".html")
    graph_report.render(data.get("cluster", {}), str(base) + "_graph.png")

    return str(base)


def action_full_analysis(cfg, cache: Cache):
    logger.console.print()
    logger.line("-", 64)
    logger.console.print("[bold bright_blue]  FULL IP ANALYSIS[/bold bright_blue]")
    logger.line("-", 64)
    logger.console.print()

    ip = ask("Enter IP address (or 'back'): ")
    if ip.lower() == "back" or not ip:
        return

    if not is_valid_ip(ip):
        logger.error(f"Invalid IP: {ip}")
        return

    cached = cache.get(ip)
    if cached:
        logger.info(f"Loaded from cache: {ip}")
        data = cached
        data["cluster"] = cluster.build(data)
    else:
        start = time.time()
        data = _run_aggregate(ip, cfg)
        elapsed = time.time() - start
        logger.ok(f"Analysis complete in {elapsed:.1f}s")
        cache.set(ip, data)
        verdict = data.get("verdict", {})
        cache.add_history(
            ip,
            verdict.get("score", 0),
            verdict.get("verdict", ""),
        )

    clear()
    console_report.print_report(data)

    base = _save_all(data, ip, cfg)

    logger.console.print()
    logger.console.print(
        f"  [{logger.BLUE}]Files saved:[/{logger.BLUE}]"
    )
    logger.console.print(f"    {base}.json")
    logger.console.print(f"    {base}.csv")
    logger.console.print(f"    {base}.html")
    logger.console.print(f"    {base}_graph.png")
    logger.console.print()


def action_pivot(cfg, cache: Cache):
    logger.console.print()
    logger.line("-", 64)
    logger.console.print("[bold bright_blue]  PIVOT FROM IP[/bold bright_blue]")
    logger.line("-", 64)
    logger.console.print()

    ip = ask("Enter IP address (or 'back'): ")
    if ip.lower() == "back" or not ip:
        return
    if not is_valid_ip(ip):
        logger.error(f"Invalid IP: {ip}")
        return

    logger.info(f"Running pivots for {ip}...")
    data = _run_aggregate(ip, cfg)
    cluster_data = cluster.build(data)

    logger.console.print()
    logger.line("=", 64)
    logger.console.print(
        "[bold bright_blue]  PIVOT SUMMARY[/bold bright_blue]"
    )
    logger.line("=", 64)

    s = cluster_data.get("stats", {})
    logger.console.print()
    logger.console.print(f"    Total IPs:      {s.get('total_ips', 0)}")
    logger.console.print(f"    Total domains:  {s.get('total_domains', 0)}")
    logger.console.print(f"    Total ASNs:     {s.get('total_asns', 0)}")
    logger.console.print(f"    Total edges:    {s.get('total_edges', 0)}")
    logger.console.print()

    fav = data.get("favicon", {})
    if fav.get("hash") is not None:
        logger.console.print(
            f"    Favicon hash:   mmh3:{fav['hash']}"
        )
    jarm_data = data.get("jarm", {})
    if jarm_data.get("jarm"):
        logger.console.print(
            f"    JARM:           {jarm_data['jarm'][:32]}..."
        )
    cert_data = data.get("cert", {})
    if cert_data.get("total_found"):
        logger.console.print(
            f"    Cert siblings:  {cert_data['total_found']}"
        )
    dns_hist = data.get("dns_history", {})
    if dns_hist.get("total_domains"):
        logger.console.print(
            f"    Reverse IP:     {dns_hist['total_domains']} domains"
        )
    bgp = data.get("bgp", {})
    if bgp.get("total_cidrs"):
        logger.console.print(
            f"    BGP CIDRs:      {bgp['total_cidrs']}"
        )

    logger.console.print()

    out_dir = Path(cfg.output.reports_dir)
    ts = time.strftime("%Y%m%d_%H%M%S")
    graph_path = out_dir / f"pivot_{ip.replace(':', '_')}_{ts}.png"
    graph_report.render(cluster_data, str(graph_path))
    logger.console.print(f"    Graph:          {graph_path}")
    logger.console.print()


def action_batch(cfg, cache: Cache):
    logger.console.print()
    logger.line("-", 64)
    logger.console.print("[bold bright_blue]  BATCH LOOKUP[/bold bright_blue]")
    logger.line("-", 64)
    logger.console.print()

    path = ask("Path to file with IPs (or 'demo'): ")
    if path.lower() == "back" or not path:
        return

    if path.lower() == "demo":
        ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        logger.info("Using demo IPs: 8.8.8.8, 1.1.1.1, 9.9.9.9")
    else:
        try:
            with open(path) as f:
                ips = [l.strip() for l in f if l.strip()
                       and is_valid_ip(l.strip())]
        except Exception as e:
            logger.error(f"Cannot read file: {e}")
            return

    if not ips:
        logger.warn("No valid IPs found")
        return

    logger.info(f"Analyzing {len(ips)} IPs...")
    results = []

    for i, ip in enumerate(ips, 1):
        logger.console.print()
        logger.console.print(
            f"  [bright_blue]-- [{i}/{len(ips)}] {ip} --[/bright_blue]"
        )

        cached = cache.get(ip)
        if cached:
            logger.info(f"  (cache hit)")
            data = cached
        else:
            data = _run_aggregate(ip, cfg)
            cache.set(ip, data)
            verdict = data.get("verdict", {})
            cache.add_history(
                ip,
                verdict.get("score", 0),
                verdict.get("verdict", ""),
            )

        v = data.get("verdict", {})
        results.append({
            "ip":     ip,
            "score":  v.get("score", 0),
            "level":  v.get("level", "?"),
            "verdict": v.get("verdict", "?"),
            "country": data.get("country", {}).get("country", ""),
        })

    logger.console.print()
    logger.line("=", 64)
    logger.console.print(
        "[bold bright_blue]  BATCH SUMMARY[/bold bright_blue]"
    )
    logger.line("=", 64)
    logger.console.print()

    rows = []
    for r in results:
        rows.append([
            r["ip"],
            r["country"][:20],
            str(r["score"]),
            r["level"],
            r["verdict"],
        ])
    logger.table("Results", ["IP", "Country", "Score", "Level", "Verdict"], rows)

    out_dir = Path(cfg.output.reports_dir)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"batch_{ts}.json"
    json_out.save({"results": results}, str(out_file))


def action_my_ip(cfg, cache: Cache):
    logger.console.print()
    logger.info("Fetching your public IP...")

    import httpx
    try:
        r = httpx.get("https://api.ipify.org?format=json", timeout=10)
        my_ip = r.json().get("ip", "")
    except Exception as e:
        logger.error(f"Cannot determine public IP: {e}")
        return

    if not my_ip:
        logger.error("No IP returned")
        return

    logger.ok(f"Your public IP: {my_ip}")

    data = _run_aggregate(my_ip, cfg)
    console_report.print_report(data)


def action_view_cache(cache: Cache):
    rows_data = cache.recent(20)
    if not rows_data:
        logger.info("Cache is empty")
        return

    rows = []
    for entry in rows_data:
        ip = entry["ip"]
        ts = time.strftime("%Y-%m-%d %H:%M",
                          time.localtime(entry["created_at"]))
        rows.append([ip, ts])
    logger.table("Recent Lookups", ["IP", "When"], rows)


def action_clear_cache(cache: Cache):
    ans = ask("Clear all cache? [y/N]: ").lower()
    if ans == "y":
        cache.clear()
        logger.ok("Cache cleared")


def action_settings(cfg):
    logger.panel("Configuration", (
        f"Timeout:           {cfg.core.timeout_seconds}s\n"
        f"Max workers:       {cfg.core.max_workers}\n"
        f"Cache TTL:         {cfg.core.cache_ttl_hours}h\n"
        f"Pivot enabled:     {cfg.pivot.enabled}\n"
        f"Pivot depth:       {cfg.pivot.depth}\n"
        f"AbuseIPDB key:     {'set' if cfg.sources.abuseipdb_key else 'missing'}\n"
        f"VirusTotal key:    {'set' if cfg.sources.virustotal_key else 'missing'}\n"
        f"GreyNoise key:     {'set' if cfg.sources.greynoise_key else 'missing'}\n"
    ))


# =============================================================
#  DISPATCHER
# =============================================================

def handle_choice(choice: str, cfg, cache: Cache):
    if choice == "0":
        logger.info("Goodbye.")
        sys.exit(0)
    elif choice == "1":
        action_full_analysis(cfg, cache)
    elif choice == "2":
        action_pivot(cfg, cache)
    elif choice == "3":
        action_batch(cfg, cache)
    elif choice == "4":
        action_my_ip(cfg, cache)
    elif choice == "5":
        action_view_cache(cache)
    elif choice == "6":
        action_clear_cache(cache)
    elif choice == "7":
        action_settings(cfg)
    else:
        logger.warn(f"Unknown option: {choice}")


def run(config_path: str = CONFIG_PATH):
    try:
        cfg = load(config_path)
    except Exception as e:
        print(f"Config error: {e}")
        print(f"Expected at: {config_path}")
        sys.exit(1)

    cache = Cache(cfg.core.cache_db, cfg.core.cache_ttl_hours)

    while True:
        clear()
        show_header()
        show_status(cache)
        logger.menu("MAIN MENU", MENU_OPTIONS)

        choice = ask("Choose [0-7]: ")
        if choice.lower() == "back" or not choice:
            continue

        handle_choice(choice, cfg, cache)

        if choice != "0":
            try:
                input("\n  Press Enter to return to menu...")
            except (KeyboardInterrupt, EOFError):
                sys.exit(0)
