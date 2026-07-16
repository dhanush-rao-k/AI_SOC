import json
from dataclasses import dataclass


@dataclass
class MitreResult:

    technique_id: str

    technique: str

    tactic: str

    description: str

    found: bool


class MitreLookup:

    def __init__(
        self,
        database_path="data/mitre_attack.json"
    ):

        with open(database_path, "r") as file:

            self.database = json.load(file)

    def lookup(
        self,
        event_type: str
    ) -> MitreResult:

        event_type = event_type.upper()

        if event_type not in self.database:

            return MitreResult(
                technique_id="N/A",
                technique="Unknown",
                tactic="Unknown",
                description="No MITRE mapping found.",
                found=False
            )

        technique = self.database[event_type]

        return MitreResult(
            technique_id=technique["technique_id"],
            technique=technique["technique"],
            tactic=technique["tactic"],
            description=technique["description"],
            found=True
        )