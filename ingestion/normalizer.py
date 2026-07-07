from __future__ import annotations


def normalize_log_fields(parsed_log: dict[str, str]) -> dict[str, str]:
    normalized_log = dict(parsed_log)
    raw_log = normalized_log.get("raw_log", "")
    normalized_log["raw_log"] = " ".join(raw_log.split())
    return normalized_log