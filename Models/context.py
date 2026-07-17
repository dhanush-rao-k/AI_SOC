from dataclasses import dataclass, field

from ingestion.metadata import Metadata
from ingestion.software import Software
from enrichment.ioc import IOC
from enrichment.models import ThreatIntel
from intelligence.risk_engine import RiskAssessment
from intelligence.confidence import ConfidenceAssessment
from vectorstore.faiss_store import SearchResult


@dataclass
class AnalysisContext:

    # ---------------------------------------
    # Original Input
    # ---------------------------------------

    raw_log: str

    # ---------------------------------------
    # Parsing
    # ---------------------------------------

    metadata: Metadata | None = None

    ioc: IOC | None = None

    software: list[Software] = field(default_factory=list)

    # ---------------------------------------
    # Retrieval
    # ---------------------------------------

    similar_logs: list[SearchResult] = field(default_factory=list)

    average_similarity: float = 0.0

    # ---------------------------------------
    # Threat Intelligence
    # ---------------------------------------

    threat_intel: ThreatIntel | None = None

    # ---------------------------------------
    # Intelligence
    # ---------------------------------------

    risk: RiskAssessment | None = None

    confidence: ConfidenceAssessment | None = None

    # ---------------------------------------
    # Final Report
    # ---------------------------------------

    incident_report = None