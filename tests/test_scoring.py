"""TryScope - tests for scoring engine"""
from tryscope.analysis import scoring


def test_abuseipdb_high_score():
    data = {"score": 95, "total_reports": 50}
    contribution, confidence, signals = scoring.score_abuseipdb(data)
    assert contribution > 20
    assert "high_abuse_score" in signals


def test_abuseipdb_whitelisted():
    data = {"score": 0, "whitelisted": True}
    contribution, _, signals = scoring.score_abuseipdb(data)
    assert contribution == 0
    assert "whitelisted" in signals


def test_virustotal_malware():
    data = {"malicious": 20, "suspicious": 5,
            "total_engines": 70, "malware_families": ["Emotet"]}
    contribution, _, signals = scoring.score_virustotal(data)
    assert contribution > 5
    assert "vt_multiple_engines" in signals
    assert "malware_family_known" in signals


def test_greynoise_malicious():
    data = {"classification": "malicious"}
    contribution, _, signals = scoring.score_greynoise(data)
    assert contribution > 0
    assert "greynoise_malicious" in signals


def test_blacklists_high_listed():
    data = {"total_listed": 6, "total_checked": 22}
    contribution, _, signals = scoring.score_blacklists(data)
    assert contribution > 10
    assert "heavily_blacklisted" in signals


def test_anonymity_proxy():
    country = {"is_proxy": True, "is_hosting": True}
    contribution, _, signals = scoring.score_anonymity(country)
    assert contribution > 5
    assert "proxy_detected" in signals


def test_compute_clean():
    data = {
        "abuseipdb": {},
        "virustotal": {},
        "greynoise": {"classification": "benign"},
        "blacklists": {"total_listed": 0, "total_checked": 20},
        "country": {},
    }
    result = scoring.compute(data)
    assert result["score"] == 0
    assert result["confidence"] in ("high", "medium", "low")


def test_compute_malicious():
    data = {
        "abuseipdb": {"score": 95, "total_reports": 50},
        "virustotal": {"malicious": 30, "suspicious": 10,
                       "total_engines": 70},
        "greynoise": {"classification": "malicious"},
        "blacklists": {"total_listed": 8, "total_checked": 22},
        "country": {"is_proxy": True, "is_hosting": True},
    }
    result = scoring.compute(data)
    assert result["score"] >= 70
    assert result["confidence"] == "high"


def test_compute_breakdown_present():
    data = {
        "abuseipdb": {"score": 50, "total_reports": 10},
        "virustotal": {}, "greynoise": {}, "blacklists": {}, "country": {},
    }
    result = scoring.compute(data)
    assert "abuseipdb" in result["breakdown"]
    assert "contribution" in result["breakdown"]["abuseipdb"]
