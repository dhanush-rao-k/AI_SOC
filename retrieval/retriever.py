from __future__ import annotations

from .scorer import score_candidate


def retrieve_candidates(current_log: str, documents: list[dict], top_k: int = 5) -> list[dict]:
    scored_candidates = []
    for document in documents:
        score = score_candidate(current_log, document.get("content", ""))
        scored_candidates.append({**document, "score": score})
    scored_candidates.sort(key=lambda candidate: candidate["score"], reverse=True)
    return scored_candidates[:top_k]