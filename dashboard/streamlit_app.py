from __future__ import annotations

from agent.soc_agent import SOCAgent


def build_dashboard_state() -> dict[str, object]:
    return {"agent": SOCAgent(), "title": "AI SOC Dashboard"}