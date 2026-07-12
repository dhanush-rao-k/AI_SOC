from __future__ import annotations


def deduplicate_events(events: list[dict]) -> list[dict]:
    seen = set()
    deduplicated = []
    for event in events:
        fingerprint = tuple(sorted(event.items()))
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduplicated.append(event)
    return deduplicated