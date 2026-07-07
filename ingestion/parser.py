from __future__ import annotations


def parse_raw_log(raw_log: str) -> dict[str, str]:
    return {"raw_log": raw_log.strip()}