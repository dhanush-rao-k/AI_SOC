from __future__ import annotations

from .metadata import extract_metadata
from .reranker import rerank_candidates
from .retriever import retrieve_candidates


def correlation_pipeline(current_log: str, documents: list[dict], top_k: int = 5) -> dict:
    metadata = extract_metadata(current_log)
    candidates = retrieve_candidates(current_log, documents, top_k=top_k)
    ranked_candidates = rerank_candidates(candidates)
    return {"metadata": metadata, "candidates": ranked_candidates}