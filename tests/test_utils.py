"""TryScope - tests for utils"""
from tryscope.utils import (
    is_valid_ip, is_private_ip, is_ipv6,
    reverse_octets, score_to_label, score_to_verdict,
    shorten, safe_int, clean_domain,
)


def test_valid_ip():
    assert is_valid_ip("8.8.8.8")
    assert is_valid_ip("2001:4860:4860::8888")
    assert not is_valid_ip("999.999.999.999")
    assert not is_valid_ip("hello")
    assert not is_valid_ip("")


def test_private_ip():
    assert is_private_ip("127.0.0.1")
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("10.0.0.1")
    assert not is_private_ip("8.8.8.8")


def test_ipv6():
    assert is_ipv6("2001:4860:4860::8888")
    assert not is_ipv6("8.8.8.8")


def test_reverse_octets():
    assert reverse_octets("1.2.3.4") == "4.3.2.1"
    assert reverse_octets("8.8.8.8") == "8.8.8.8"
    assert reverse_octets("2001:4860::1") == ""


def test_score_labels():
    assert score_to_label(95) == "CRITICAL"
    assert score_to_label(70) == "HIGH"
    assert score_to_label(45) == "MEDIUM"
    assert score_to_label(25) == "LOW"
    assert score_to_label(5)  == "CLEAN"


def test_verdicts():
    assert score_to_verdict(90) == "MALICIOUS"
    assert score_to_verdict(45) == "SUSPICIOUS"
    assert score_to_verdict(10) == "CLEAN"


def test_shorten():
    assert shorten("hello", 10) == "hello"
    assert len(shorten("a" * 100, 10)) <= 10
    assert shorten("", 10) == ""


def test_safe_int():
    assert safe_int("42") == 42
    assert safe_int("abc", 0) == 0
    assert safe_int(None, -1) == -1


def test_clean_domain():
    assert clean_domain("https://example.com/path") == "example.com"
    assert clean_domain("EXAMPLE.COM") == "example.com"
    assert clean_domain("http://test.org:8080/x") == "test.org:8080"
