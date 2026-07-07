from __future__ import annotations

from vectorstore.document_store import DocumentRecord, save_document_store

from .normalizer import normalize_log_fields
from .parser import parse_raw_log


def ingest_log(raw_log: str, document_id: str, metadata: dict | None = None) -> DocumentRecord:
    parsed_log = parse_raw_log(raw_log)
    normalized_log = normalize_log_fields(parsed_log)
    record = DocumentRecord(
        document_id=document_id,
        content=normalized_log["raw_log"],
        metadata=metadata or {},
    )
    save_document_store([record])
    return record