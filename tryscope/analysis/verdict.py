"""
TryScope - Final verdict
Maps the risk score to a verdict + MITRE ATT&CK techniques.
"""

VERDICTS = [
    (80, "CRITICAL",  "MALICIOUS",  "Block immediately"),
    (60, "HIGH",      "MALICIOUS",  "Block recommended"),
    (40, "MEDIUM",    "SUSPICIOUS", "Investigate before allowing"),
    (20, "LOW",       "SUSPICIOUS", "Monitor"),
    (0,  "CLEAN",     "CLEAN",      "No action required"),
]

# Signal -> MITRE technique mapping
SIGNAL_TO_MITRE = {
    "high_abuse_score":       "T1583.003 (Acquire Infrastructure: VPS)",
    "many_reports":           "T1595 (Active Scanning)",
    "vt_multiple_engines":    "T1587.001 (Develop Capabilities: Malware)",
    "malware_family_known":   "T1587.001 (Develop Capabilities: Malware)",
    "greynoise_malicious":    "T1595 (Active Scanning)",
    "greynoise_noise":        "T1595.002 (Vulnerability Scanning)",
    "multiple_blacklists":    "T1583 (Acquire Infrastructure)",
    "heavily_blacklisted":    "T1583.003 (Acquire Infrastructure: VPS)",
    "proxy_detected":         "T1090 (Proxy)",
    "datacenter_host":        "T1583.003 (Acquire Infrastructure: VPS)",
}


def compute(score_data: dict, aggregated: dict) -> dict:
    """
    Return the verdict object.
    """
    score = score_data.get("score", 0)
    signals = score_data.get("signals", [])

    level = "CLEAN"
    verdict = "CLEAN"
    recommendation = "No action required"
    for threshold, lvl, vrd, rec in VERDICTS:
        if score >= threshold:
            level = lvl
            verdict = vrd
            recommendation = rec
            break

    mitre = []
    for s in signals:
        tech = SIGNAL_TO_MITRE.get(s)
        if tech and tech not in mitre:
            mitre.append(tech)

    return {
        "score":          score,
        "level":          level,
        "verdict":        verdict,
        "confidence":     score_data.get("confidence", "medium"),
        "recommendation": recommendation,
        "signals":        signals,
        "mitre":          mitre,
        "breakdown":      score_data.get("breakdown", {}),
    }
