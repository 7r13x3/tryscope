"""
TryScope - Config loader
"""
import sys
from dataclasses import dataclass, field
from typing import List

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


@dataclass
class CoreCfg:
    timeout_seconds: int = 10
    max_workers: int = 20
    cache_ttl_hours: int = 24
    cache_db: str = "cache/tryscope.db"


@dataclass
class OutputCfg:
    reports_dir: str = "reports"
    default_format: str = "all"
    auto_open_html: bool = False


@dataclass
class SourcesCfg:
    ip_api: bool = True
    ipwhois: bool = True
    rdap: bool = True
    internetdb: bool = True
    restcountries: bool = True
    abuseipdb_key: str = ""
    virustotal_key: str = ""
    greynoise_key: str = ""


@dataclass
class PivotCfg:
    enabled: bool = True
    depth: int = 2
    max_ips: int = 500
    favicon_pivot: bool = True
    jarm_pivot: bool = True
    cert_pivot: bool = True
    dns_pivot: bool = True
    bgp_pivot: bool = True


@dataclass
class BlacklistCfg:
    lists: List[str] = field(default_factory=lambda: [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "b.barracudacentral.org",
        "dnsbl.sorbs.net",
        "cbl.abuseat.org",
    ])


@dataclass
class WhitelistCfg:
    ips: List[str] = field(default_factory=lambda: [
        "127.0.0.1", "8.8.8.8", "1.1.1.1",
    ])


@dataclass
class Config:
    core: CoreCfg = field(default_factory=CoreCfg)
    output: OutputCfg = field(default_factory=OutputCfg)
    sources: SourcesCfg = field(default_factory=SourcesCfg)
    pivot: PivotCfg = field(default_factory=PivotCfg)
    blacklist: BlacklistCfg = field(default_factory=BlacklistCfg)
    whitelist: WhitelistCfg = field(default_factory=WhitelistCfg)


def load(path: str) -> Config:
    with open(path, "rb") as f:
        data = tomllib.load(f)

    def g(sec, key, default):
        return data.get(sec, {}).get(key, default)

    cfg = Config(
        core=CoreCfg(
            timeout_seconds=int(g("core", "timeout_seconds", 10)),
            max_workers=int(g("core", "max_workers", 20)),
            cache_ttl_hours=int(g("core", "cache_ttl_hours", 24)),
            cache_db=g("core", "cache_db", "cache/tryscope.db"),
        ),
        output=OutputCfg(
            reports_dir=g("output", "reports_dir", "reports"),
            default_format=g("output", "default_format", "all"),
            auto_open_html=bool(g("output", "auto_open_html", False)),
        ),
        sources=SourcesCfg(
            ip_api=bool(g("sources", "ip_api", True)),
            ipwhois=bool(g("sources", "ipwhois", True)),
            rdap=bool(g("sources", "rdap", True)),
            internetdb=bool(g("sources", "internetdb", True)),
            restcountries=bool(g("sources", "restcountries", True)),
            abuseipdb_key=g("sources", "abuseipdb_key", ""),
            virustotal_key=g("sources", "virustotal_key", ""),
            greynoise_key=g("sources", "greynoise_key", ""),
        ),
        pivot=PivotCfg(
            enabled=bool(g("pivot", "enabled", True)),
            depth=int(g("pivot", "depth", 2)),
            max_ips=int(g("pivot", "max_ips", 500)),
            favicon_pivot=bool(g("pivot", "favicon_pivot", True)),
            jarm_pivot=bool(g("pivot", "jarm_pivot", True)),
            cert_pivot=bool(g("pivot", "cert_pivot", True)),
            dns_pivot=bool(g("pivot", "dns_pivot", True)),
            bgp_pivot=bool(g("pivot", "bgp_pivot", True)),
        ),
        blacklist=BlacklistCfg(
            lists=list(g("blacklist", "lists", [
                "zen.spamhaus.org",
                "bl.spamcop.net",
                "b.barracudacentral.org",
                "dnsbl.sorbs.net",
                "cbl.abuseat.org",
            ])),
        ),
        whitelist=WhitelistCfg(
            ips=list(g("whitelist", "ips",
                       ["127.0.0.1", "8.8.8.8", "1.1.1.1"])),
        ),
    )
    return cfg
