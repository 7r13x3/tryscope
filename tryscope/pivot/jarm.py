"""
TryScope - JARM TLS fingerprint
JARM sends 10 specially crafted TLS ClientHello packets and hashes
the responses. The result is a fingerprint of the server's TLS stack.

Requires: raw socket access (no scapy needed — pure Python).
Note: Full JARM requires 10 TLS ClientHellos. We implement a
simplified 4-hello version for reliability across systems.
"""
import hashlib
import socket
import ssl
from typing import Optional

from .. import logger


# 4 different TLS ClientHello configurations
# (TLS version, cipher list, extensions pattern)
CLIENT_HELLOS = [
    # Standard modern client
    {
        "name":    "tls12_modern",
        "version": ssl.TLSVersion.TLSv1_2,
        "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM",
    },
    {
        "name":    "tls13_only",
        "version": ssl.TLSVersion.TLSv1_3,
        "ciphers": "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
    },
    {
        "name":    "tls10_legacy",
        "version": ssl.TLSVersion.TLSv1,
        "ciphers": "ALL:!aNULL:!eNULL",
    },
    {
        "name":    "empty_ciphers",
        "version": ssl.TLSVersion.TLSv1_2,
        "ciphers": "NULL",
    },
]


def _tls_probe(host: str, port: int, version, ciphers: str,
               timeout: float = 5) -> str:
    """Perform a single TLS handshake and return a signature string."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except Exception:
            pass
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError:
            pass

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ver = ssock.version() or "?"
                cipher = ssock.cipher() or ("?", "?", "?")
                return f"{ver}|{cipher[0]}|{cipher[1]}"
    except Exception as e:
        return f"err:{type(e).__name__}"


def compute_jarm(host: str, port: int = 443,
                 timeout: float = 5) -> Optional[str]:
    """
    Compute a simplified JARM fingerprint.
    Returns a 62-character hex string (or None on total failure).
    """
    parts = []
    for hello in CLIENT_HELLOS:
        sig = _tls_probe(host, port, hello["version"],
                         hello["ciphers"], timeout)
        parts.append(sig)

    combined = "|".join(parts)
    if combined.count("err:") >= 3:
        return None

    digest = hashlib.sha256(combined.encode()).hexdigest()
    return digest[:62]


def pivot(ip: str, port: int = 443, timeout: float = 5) -> dict:
    """
    Compute JARM fingerprint for an IP.
    Returns {jarm, port, raw_signature}.
    """
    jarm = compute_jarm(ip, port, timeout)
    if not jarm:
        return {}

    logger.ok(f"JARM: {jarm[:16]}...")

    return {
        "jarm":       jarm,
        "port":       port,
        "note":       "simplified 4-hello JARM (full JARM uses 10 hellos)",
        "shodan_query": f"ssl.jarm:{jarm}",
    }
