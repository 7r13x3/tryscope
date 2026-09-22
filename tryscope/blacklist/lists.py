"""
TryScope - DNSBL list definitions
Curated list of public, free DNS-based blacklists.
"""

# Each entry: (zone, name, category, tier)
# tier: 1 = critical, 2 = standard, 3 = aggressive (may have false positives)

DNSBL_LISTS = [
    # --- Tier 1: High-confidence, well-maintained ---
    ("zen.spamhaus.org",            "Spamhaus ZEN",          "spam",      1),
    ("bl.spamcop.net",              "SpamCop",               "spam",      1),
    ("b.barracudacentral.org",      "Barracuda",             "spam",      1),
    ("cbl.abuseat.org",             "CBL (Composite)",       "spam",      1),
    ("dnsbl.sorbs.net",             "SORBS",                 "spam",      1),
    ("spam.dnsbl.sorbs.net",        "SORBS Spam",            "spam",      1),
    ("dnsbl-1.uceprotect.net",      "UCEPROTECT L1",         "spam",      1),
    ("psbl.surriel.com",            "PSBL",                  "spam",      1),

    # --- Tier 2: Standard ---
    ("dnsbl-2.uceprotect.net",      "UCEPROTECT L2",         "spam",      2),
    ("dnsbl-3.uceprotect.net",      "UCEPROTECT L3",         "spam",      2),
    ("bl.blocklist.de",             "Blocklist.de",          "attack",    2),
    ("ips.backscatterer.org",       "Backscatterer",         "spam",      2),
    ("all.s5h.net",                 "S5H",                   "spam",      2),
    ("spamsources.fabel.dk",        "SpamSources",           "spam",      2),
    ("dnsbl.dronebl.org",           "DroneBL",               "botnet",    2),
    ("rbl.efnetrbl.org",            "EFnet RBL",             "proxy",     2),
    ("ips.whitelisted.org",         "whitelisted.org",       "spam",      2),
    ("dnsbl.kempt.net",             "Kempt",                 "spam",      2),
    ("blackholes.mail-abuse.org",   "Mail-Abuse",            "spam",      2),
    ("relays.mail-abuse.org",       "Mail-Abuse Relay",      "spam",      2),

    # --- Tier 3: Aggressive / may have false positives ---
    ("spam.spamrats.com",           "SpamRats",              "spam",      3),
    ("noptr.spamrats.com",          "SpamRats no-PTR",       "spam",      3),
    ("dyna.spamrats.com",           "SpamRats dynamic",      "spam",      3),
    ("spam.spamrats.com",           "SpamRats",              "spam",      3),
    ("dnsbl.tornevall.org",         "Tornevall",             "spam",      3),
    ("query.senderbase.org",        "SenderBase",            "spam",      3),
    ("dnsrbl.org",                  "DNSRBL",                "spam",      3),
    ("new.spam.dnsbl.sorbs.net",    "SORBS new",             "spam",      3),
    ("recent.spam.dnsbl.sorbs.net", "SORBS recent",          "spam",      3),

    # --- Additional ---
    ("bl.emailbasura.org",          "EmailBasura",           "spam",      2),
    ("dnsbl.cyberlogic.net",        "Cyberlogic",            "spam",      2),
    ("rbl.schulte.org",             "Schulte",               "spam",      2),
]


# Response codes from DNSBLs (common values)
DNSBL_CODES = {
    "127.0.0.2":  "spam source",
    "127.0.0.3":  "spam source (alt)",
    "127.0.0.4":  "spam source",
    "127.0.0.10": "proxy",
    "127.0.0.11": "proxy (alt)",
    "127.0.0.12": "proxy (alt)",
    "127.0.0.13": "proxy (alt)",
    "127.0.0.14": "proxy (alt)",
    "127.0.0.20": "spam source",
    "127.0.0.100": "spam source",
    "127.0.0.200": "blocked",
    "127.0.1.0":  "spam source",
    "127.0.2.0":  "spam source",
    "127.0.3.0":  "spam source",
    "127.0.4.0":  "spam source",
    "127.0.4.1":  "spam source",
    "127.0.4.2":  "spam source",
    "127.0.4.3":  "spam source",
    "127.0.4.4":  "spam source",
    "127.0.4.5":  "spam source",
    "127.0.4.6":  "spam source",
    "127.0.4.7":  "spam source",
    "127.0.4.8":  "spam source",
    "127.0.4.9":  "spam source",
    "127.0.4.10": "spam source",
    "127.0.4.11": "spam source",
    "127.0.4.12": "spam source",
    "127.0.4.13": "spam source",
    "127.0.4.14": "spam source",
    "127.0.4.15": "spam source",
    "127.0.4.16": "spam source",
    "127.0.4.17": "spam source",
    "127.0.4.18": "spam source",
    "127.0.4.19": "spam source",
    "127.0.4.20": "spam source",
    "127.0.4.21": "spam source",
    "127.0.4.22": "spam source",
    "127.0.4.23": "spam source",
    "127.0.4.24": "spam source",
    "127.0.4.25": "spam source",
    "127.0.4.26": "spam source",
    "127.0.4.27": "spam source",
    "127.0.4.28": "spam source",
    "127.0.4.29": "spam source",
    "127.0.4.30": "spam source",
    "127.0.0.0":  "listed",
    "127.0.0.1":  "listed",
}
