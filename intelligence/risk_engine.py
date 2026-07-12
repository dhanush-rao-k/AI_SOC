from __future__ import annotations


def calculate_risk_score(severity: str = "low", confidence: int = 0) -> int:
    severity_weights = {"low": 20, "medium": 50, "high": 80, "critical": 100}
    base_score = severity_weights.get(severity.lower(), 20)
    return min(100, max(0, int((base_score + confidence) / 2)))