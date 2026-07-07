from __future__ import annotations

from agent.soc_agent import SOCAgent


def health_check() -> dict[str, str]:
    return {"status": "ok"}


def analyze_log(current_log: str, retrieved_logs: str = ""):
    agent = SOCAgent()
    return agent.analyze(current_log=current_log, retrieved_logs=retrieved_logs)