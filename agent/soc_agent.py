from __future__ import annotations

from llm.chain import create_chain


class SOCAgent:
    def __init__(self, chain=None):
        self.chain = chain or create_chain()

    def analyze(self, current_log: str, retrieved_logs: str = ""):
        return self.chain.invoke(
            {"current_log": current_log, "retrieved_logs": retrieved_logs}
        )