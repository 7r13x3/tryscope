"""
TryScope - Risk scoring
Combines signals from every source into a single 0-100 risk score.
"""

# Weight for each source's contribution to the final score
WEIGHTS = {
    "abuseipdb":    30,
    "virustotal":   25,
    "greynoise":    15,
    "blacklists":   20,
    "anonymity":    10,
}

# Confidence multipliers
CONFIDENCE = {
    "high":   1.0,
    "medium": 0.7,
    "low":    0.4,
}


def score_abuseipdb(data: dict) -> tuple:
    """Return (contribution, confidence, signals)."""
    if not data:
        return 0.0, "low", []
    score = data.get("score", 0)
    if score == 0:
        return 0.0, "high", []
    signals = []
    if score >= 75:
        signals.append("high_abuse_score")
    if data.get("total_reports", 0) > 10:
        signals.append("many_reports")
    if data.get("whitelisted"):
        return 0.0, "high", ["whitelisted"]
    contribution = (score / 100.0) * WEIGHTS["abuseipdb"]
    return contribution, "high", signals


def score_virustotal(data: dict) -> tuple:
    if not data:
        return 0.0, "low", []
    malicious = data.get("malicious", 0)
    suspicious = data.get("suspicious", 0)
    total = data.get("total_engines", 1) or 1
    ratio = (malicious + suspicious * 0.5) / total
    signals = []
    if malicious >= 5:
        signals.append("vt_multiple_engines")
    if data.get("malware_families"):
        signals.append("malware_family_known")
    contribution = min(ratio * 4, 1.0) * WEIGHTS["virustotal"]
    return contribution, "high", signals


def score_greynoise(data: dict) -> tuple:
    if not data:
        return 0.0, "low", []
    signals = []
    cls = data.get("classification", "unknown").lower()
    if cls == "malicious":
        signals.append("greynoise_malicious")
        return WEIGHTS["greynoise"], "high", signals
    if cls == "benign":
        return 0.0, "medium", ["greynoise_benign"]
    if data.get("noise"):
        signals.append("greynoise_noise")
        return WEIGHTS["greynoise"] * 0.5, "medium", signals
    return 0.0, "low", []


def score_blacklists(data: dict) -> tuple:
    if not data:
        return 0.0, "low", []
    listed = data.get("total_listed", 0)
    checked = data.get("total_checked", 1) or 1
    signals = []
    if listed >= 3:
        signals.append("multiple_blacklists")
    if listed >= 5:
        signals.append("heavily_blacklisted")
    ratio = min(listed / 5.0, 1.0)
    contribution = ratio * WEIGHTS["blacklists"]
    return contribution, "medium", signals


def score_anonymity(country: dict) -> tuple:
    if not country:
        return 0.0, "low", []
    signals = []
    anon_count = 0
    if country.get("is_proxy"):
        anon_count += 1
        signals.append("proxy_detected")
    if country.get("is_hosting"):
        anon_count += 1
        signals.append("datacenter_host")
    contribution = (anon_count / 2.0) * WEIGHTS["anonymity"]
    return contribution, "medium", signals


def compute(aggregated: dict) -> dict:
    """
    Take the aggregated result and compute a final risk score.
    Returns {score, confidence, signals, breakdown}.
    """
    breakdown = {}

    abuse_data = aggregated.get("abuseipdb", {})
    vt_data = aggregated.get("virustotal", {})
    gn_data = aggregated.get("greynoise", {})
    bl_data = aggregated.get("blacklists", {})
    country = aggregated.get("country", {})

    total = 0.0
    signals = []

    c, conf, sig = score_abuseipdb(abuse_data)
    breakdown["abuseipdb"] = {"contribution": round(c, 1), "confidence": conf}
    total += c
    signals += sig

    c, conf, sig = score_virustotal(vt_data)
    breakdown["virustotal"] = {"contribution": round(c, 1), "confidence": conf}
    total += c
    signals += sig

    c, conf, sig = score_greynoise(gn_data)
    breakdown["greynoise"] = {"contribution": round(c, 1), "confidence": conf}
    total += c
    signals += sig

    c, conf, sig = score_blacklists(bl_data)
    breakdown["blacklists"] = {"contribution": round(c, 1), "confidence": conf}
    total += c
    signals += sig

    c, conf, sig = score_anonymity(country)
    breakdown["anonymity"] = {"contribution": round(c, 1), "confidence": conf}
    total += c
    signals += sig

    score = int(min(total, 100))

    if score >= 70:
        confidence = "high"
    elif score >= 40:
        confidence = "medium"
    else:
        confidence = "high"

    return {
        "score":      score,
        "confidence": confidence,
        "signals":    sorted(set(signals)),
        "breakdown":  breakdown,
    }
