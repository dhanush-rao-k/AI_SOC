from __future__ import annotations


def lookup_geoip(ip_address: str) -> dict[str, str]:
    return {"ip_address": ip_address, "country": "unknown", "source": "geoip"}