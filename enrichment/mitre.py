import json
from dataclasses import dataclass

from config import MITRE_DATABASE_PATH


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
        database_path=MITRE_DATABASE_PATH
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

        techniques = self.database[event_type]

        if not techniques:

            return MitreResult(
                technique_id="N/A",
                technique="Unknown",
                tactic="Unknown",
                description="No MITRE mapping found.",
                found=False
            )

        # TODO: support returning multiple techniques per event_type
        # Currently returns only the first match.
        technique = techniques[0]

        return MitreResult(
            technique_id=technique["technique_id"],
            technique=technique["name"],
            tactic=technique["tactic"],
            description=technique["description"],
            found=True
        )