from __future__ import annotations


def calculate_confidence(evidence_count: int) -> int:
    return max(0, min(100, evidence_count * 10))