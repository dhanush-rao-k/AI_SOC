from __future__ import annotations

from tools.abuseipdb import lookup_abuseipdb


def build_tool_registry() -> dict[str, object]:
    return {"abuseipdb": lookup_abuseipdb}