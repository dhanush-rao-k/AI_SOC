from __future__ import annotations


def rerank_candidates(candidates: list[dict]) -> list[dict]:
    return sorted(candidates, key=lambda candidate: candidate.get("score", 0), reverse=True)