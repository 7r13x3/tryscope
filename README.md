# TryScope

> Trace any IP to its infrastructure cluster.

TryScope takes a single IP and returns the entire infrastructure cluster around it pivoting through favicon hashes, TLS fingerprints, certificates, passive DNS, and BGP history.
 185.220.101.1 ]
|
+-- geo + ASN + reputation + blacklists
|
+-- favicon hash --> 40 more IPs
+-- JARM hash --> 12 more IPs
+-- cert SAN --> 5 domains
+-- passive DNS --> 7 previous IPs
+-- ASN neighbors --> 8 more hosts
|
[ 112-IP cluster -- 79% malicious ]

---

## Features

| Layer | Capability |
|---|---|
| **Core** | Geo, ISP, ASN, rDNS, RDAP, InternetDB |
| **Country** | ISO codes, currency, calling code, borders |
| **Reputation** | AbuseIPDB, VirusTotal, GreyNoise |
| **Blacklists** | 30+ DNS-based lists |
| **Anonymity** | Tor, VPN, Proxy, Datacenter detection |
| **Pivot** | Favicon MMH3, JARM, Cert SAN, Passive DNS, BGP |
| **Analysis** | Multi-source scoring, risk decay, verdict |
| **Reports** | Console, HTML + map, cluster graph, JSON, CSV |
| **Interfaces** | CLI + interactive menu |

---

## Legal Disclaimer

TryScope only reads **publicly published** threat intelligence APIs. It does not scan, probe, or send any traffic to the target IP. It is a passive intelligence aggregation tool.

---

## Installation

```bash
git clone https://github.com/7r13x3/tryscope.git
cd tryscope
pip install -r requirements.txt
Requires Python 3.10+.
Usage
Interactive Menu (recommended)
python -m tryscope
  [ 1 ]   Full IP Analysis     (all features, one IP)
  [ 2 ]   Pivot from IP         (infrastructure hunting)
  [ 3 ]   Batch lookup          (file with many IPs)
  [ 4 ]   My public IP
  [ 5 ]   View cache
  [ 6 ]   Settings
  [ 0 ]   Exit
Press 1, type an IP, press Enter. Everything else is automatic.
CLI Commands
python -m tryscope lookup 185.220.101.1
python -m tryscope pivot  185.220.101.1 --depth 2
python -m tryscope batch  --file ips.txt
python -m tryscope report --ip 185.220.101.1 --html
