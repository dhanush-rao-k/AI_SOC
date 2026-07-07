from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IncidentMemory:
    incidents: list[dict] = field(default_factory=list)

    def add(self, incident: dict) -> None:
        self.incidents.append(incident)

    def all(self) -> list[dict]:
        return list(self.incidents)