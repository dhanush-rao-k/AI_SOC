from __future__ import annotations


def lookup_abuseipdb(ip_address: str) -> dict[str, str]:
    return {"ip_address": ip_address, "abuse_confidence": "unknown", "source": "abuseipdb"}