from __future__ import annotations


def map_to_mitre(attack_type: str) -> dict[str, str]:
    return {"attack_type": attack_type, "technique": "unknown"}