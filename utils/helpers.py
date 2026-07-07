from __future__ import annotations


def ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]