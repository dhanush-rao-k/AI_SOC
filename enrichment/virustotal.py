from __future__ import annotations


def lookup_virustotal(indicator: str) -> dict[str, str]:
    return {"indicator": indicator, "source": "virustotal", "reputation": "unknown"}