from __future__ import annotations


def lookup_cve(software_name: str) -> list[dict[str, str]]:
    return [{"software": software_name, "cve": "unknown"}]