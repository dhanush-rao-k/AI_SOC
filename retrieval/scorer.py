from __future__ import annotations


def score_candidate(current_log: str, candidate_log: str, metadata_overlap: int = 0) -> float:
    current_tokens = set(current_log.lower().split())
    candidate_tokens = set(candidate_log.lower().split())
    lexical_overlap = len(current_tokens & candidate_tokens)
    return float(lexical_overlap + metadata_overlap)