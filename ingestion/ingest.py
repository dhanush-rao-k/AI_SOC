from __future__ import annotations

from .metadata import MetadataExtractor
from .normalizer import normalize_log_fields
from .parser import parse_raw_log


def ingest_log(raw_log: str, document_id: str, metadata: dict | None = None) -> dict:
    parsed_log = parse_raw_log(raw_log)
    normalized_log = normalize_log_fields(parsed_log)
    extractor = MetadataExtractor()
    extracted_metadata = extractor.extract(normalized_log["raw_log"])
    return {
        "document_id": document_id,
        "content": normalized_log["raw_log"],
        "metadata": {**extracted_metadata, **(metadata or {})},
    }