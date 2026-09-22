"""
TryScope - Utilities
"""
import ipaddress
import re
import socket
from typing import Optional


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except ValueError:
        return False


def is_ipv6(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip),
                          ipaddress.IPv6Address)
    except ValueError:
        return False


def reverse_octets(ip: str) -> str:
    """Return IP octets in reverse (for DNSBL queries)."""
    if is_ipv6(ip):
        return ""
    return ".".join(reversed(ip.split(".")))


def resolve_hostname(hostname: str, timeout: int = 5) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def shorten(text: str, n: int = 60) -> str:
    if not text:
        return ""
    text = str(text)
    return text if len(text) <= n else text[: n - 3] + "..."


def score_to_label(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "CLEAN"


def score_to_verdict(score: int) -> str:
    if score >= 60:
        return "MALICIOUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "CLEAN"


def safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def clean_domain(text: str) -> str:
    text = str(text or "").strip().lower()
    text = re.sub(r"^https?://", "", text)
    text = text.split("/")[0]
    return text
