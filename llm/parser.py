from typing import List

from pydantic import BaseModel, Field
from langchain_core.output_parsers import PydanticOutputParser


class IncidentReport(BaseModel):

    is_incident: bool

    severity: str

    confidence: int = Field(ge=0, le=100)

    attack_type: str

    mitre_technique: str

    source_ip: str

    destination_ip: str

    source_port: str

    destination_port: str

    protocol: str

    affected_asset: str

    indicators_of_compromise: List[str]

    threat_intelligence: str

    geo_location: str

    virustotal_reputation: str

    risk_score: int = Field(ge=0, le=100)

    summary: str

    reasoning: str

    recommendation: str

    recommended_actions: List[str]

    similar_incidents_found: int

    related_attack_patterns: List[str]


parser = PydanticOutputParser(
    pydantic_object=IncidentReport
)


def get_parser():
    return parser