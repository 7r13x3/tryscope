"""
TryScope - Console report
Blue & white ASCII output.
"""
from .. import logger
from ..utils import score_to_verdict


def _field(label, value):
    if value in (None, "", [], 0, 0.0):
        return
    logger.console.print(
        f"    [{logger.WHITE_DIM}]{label:<20}[/{logger.WHITE_DIM}]"
        f"[{logger.WHITE}]{value}[/{logger.WHITE}]"
    )


def _section(name):
    logger.console.print()
    logger.console.print(f"[bold {logger.BLUE}]  {name}[/bold {logger.BLUE}]")


def print_report(data: dict):
    ip = data.get("ip", "?")
    logger.report_header(ip)

    country = data.get("country", {}) or {}
    rdap = data.get("rdap", {}) or {}
    internetdb = data.get("internetdb", {}) or {}
    abuse = data.get("abuseipdb", {}) or {}
    vt = data.get("virustotal", {}) or {}
    gn = data.get("greynoise", {}) or {}
    bl = data.get("blacklists", {}) or {}
    favicon = data.get("favicon", {}) or {}
    jarm_data = data.get("jarm", {}) or {}
    cert_data = data.get("cert", {}) or {}
    dns_hist = data.get("dns_history", {}) or {}
    bgp = data.get("bgp", {}) or {}
    verdict = data.get("verdict", {}) or {}
    cluster = data.get("cluster", {}) or {}

    # --- GEOLOCATION ---
    _section("GEOLOCATION")
    _field("Country", country.get("country"))
    code = country.get("country_code")
    code3 = country.get("country_code3")
    if code and code3:
        _field("Country code", f"{code} / {code3}")
    _field("Region", country.get("region"))
    _field("City", country.get("city"))
    _field("Postal code", country.get("postal"))
    lat, lon = country.get("lat", 0), country.get("lon", 0)
    if lat or lon:
        _field("Coordinates", f"{lat}, {lon}")
    _field("Continent", country.get("continent"))
    _field("Timezone", country.get("timezone"))
    _field("UTC offset", country.get("timezone_utc"))
    _field("Local time", country.get("local_time"))
    _field("Day phase", country.get("day_phase"))
    if country.get("google_maps_url"):
        _field("Google Maps", country["google_maps_url"])
    if country.get("osm_url"):
        _field("OpenStreetMap", country["osm_url"])

    # --- COUNTRY ---
    if any([country.get("capital"), country.get("currency_code"),
            country.get("calling_code"), country.get("population")]):
        _section("COUNTRY")
        _field("Capital", country.get("capital"))
        _field("Population", f"{country.get('population', 0):,}"
               if country.get("population") else "")
        if country.get("currency_code"):
            _field("Currency",
                   f"{country['currency_code']} - "
                   f"{country.get('currency_name', '')} "
                   f"{country.get('currency_symbol', '')}")
        _field("Calling code", country.get("calling_code"))
        langs = country.get("languages", [])
        if langs:
            _field("Languages", ", ".join(langs[:5]))
        borders = country.get("borders", [])
        if borders:
            _field("Borders", ", ".join(borders[:10]))

    # --- NETWORK ---
    _section("NETWORK")
    _field("ISP", country.get("isp"))
    _field("Organization", country.get("org") or rdap.get("organization"))
    _field("ASN", country.get("asn"))
    if bgp.get("target_prefix"):
        _field("CIDR", bgp["target_prefix"])
    _field("Reverse DNS", country.get("reverse_dns"))
    if rdap.get("handle"):
        _field("RDAP handle", rdap["handle"])
    if rdap.get("country"):
        _field("RDAP country", rdap["country"])

    # --- REPUTATION ---
    _section("REPUTATION")
    if abuse:
        _field("AbuseIPDB", f"{abuse.get('score', 0)}/100 "
                            f"({abuse.get('total_reports', 0)} reports)")
    if vt:
        _field("VirusTotal", f"{vt.get('malicious', 0)}/"
                             f"{vt.get('total_engines', 0)} engines")
        if vt.get("malware_families"):
            _field("Malware families", ", ".join(vt["malware_families"][:3]))
    if gn:
        _field("GreyNoise", gn.get("classification", "").upper())
    if bl:
        _field("Blacklists", f"{bl.get('total_listed', 0)}/"
                             f"{bl.get('total_checked', 0)} lists")

    # --- ANONYMITY ---
    _section("ANONYMITY")
    _field("Proxy", "YES" if country.get("is_proxy") else "no")
    _field("Datacenter", "YES" if country.get("is_hosting") else "no")
    _field("Mobile", "YES" if country.get("is_mobile") else "no")

    # --- OPEN PORTS ---
    if internetdb.get("ports"):
        _section("OPEN PORTS")
        _field("Ports", ", ".join(str(p)
               for p in internetdb["ports"][:30]))
        if internetdb.get("hostnames"):
            _field("Hostnames", ", ".join(internetdb["hostnames"][:5]))
        if internetdb.get("vulns"):
            _field("CVEs", ", ".join(internetdb["vulns"][:5]))
        if internetdb.get("tags"):
            _field("Tags", ", ".join(internetdb["tags"][:5]))

    # --- PIVOT RESULTS ---
    _section("PIVOT")
    if favicon.get("hash") is not None:
        _field("Favicon hash", f"mmh3:{favicon['hash']}")
    if jarm_data.get("jarm"):
        _field("JARM", jarm_data["jarm"][:32] + "...")
    if cert_data.get("total_found"):
        _field("Cert siblings", f"{cert_data['total_found']} domains")
    if dns_hist.get("total_domains"):
        _field("Reverse IP", f"{dns_hist['total_domains']} domains")
    if bgp.get("total_cidrs"):
        _field("BGP CIDRs", f"{bgp['total_cidrs']} ranges")

    # --- CLUSTER ---
    if cluster and cluster.get("stats"):
        _section("CLUSTER")
        s = cluster["stats"]
        _field("Total IPs", s.get("total_ips", 0))
        _field("Total domains", s.get("total_domains", 0))
        _field("Total ASNs", s.get("total_asns", 0))

    # --- VERDICT ---
    _section("VERDICT")
    level = verdict.get("level", "CLEAN")
    score = verdict.get("score", 0)
    logger.console.print()
    logger.console.print(
        f"    [bold {logger.BLUE}]  [{level}]  "
        f"score {score}/100  "
        f"confidence {verdict.get('confidence', 'low').upper()}"
        f"[/bold {logger.BLUE}]"
    )
    logger.console.print()
    if verdict.get("recommendation"):
        _field("Action", verdict["recommendation"])
    if verdict.get("mitre"):
        for m in verdict["mitre"][:5]:
            _field("MITRE", m)

    logger.line("=", 64)
