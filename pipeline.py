from models.context import AnalysisContext

from ingestion.metadata import MetadataExtractor
from ingestion.software import SoftwareExtractor

from enrichment.ioc import IOCExtractor
from enrichment.engine import EnrichmentEngine

from retrieval.retriever import HybridRetriever

from intelligence.risk_engine import RiskEngine
from intelligence.confidence import ConfidenceEngine

from llm.chain import create_chain


class AISOCPipeline:

    def __init__(
        self,
        vector_store
    ):

        self.metadata_extractor = MetadataExtractor()

        self.ioc_extractor = IOCExtractor()

        self.software_extractor = SoftwareExtractor()

        self.retriever = HybridRetriever(
            vector_store
        )

        self.enrichment_engine = EnrichmentEngine()

        self.risk_engine = RiskEngine()

        self.confidence_engine = ConfidenceEngine()

        self.chain = create_chain()

    def analyze(
        self,
        log: str
    ) -> AnalysisContext:

        context = AnalysisContext(
            raw_log=log
        )

        # ---------------------------------
        # Metadata
        # ---------------------------------

        context.metadata = self.metadata_extractor.extract_metadata(
            context.raw_log
        )

        # ---------------------------------
        # IOC Extraction
        # ---------------------------------

        context.ioc = self.ioc_extractor.extract_iocs(
            context.raw_log
        )

        # ---------------------------------
        # Software Extraction
        # ---------------------------------

        context.software = self.software_extractor.extract(
            context.raw_log
        )

        # ---------------------------------
        # Retrieval
        # ---------------------------------

        context.similar_logs = self.retriever.retrieve(
            context
        )

        if context.similar_logs:

            context.average_similarity = sum(

                result.similarity

                for result in context.similar_logs

            ) / len(context.similar_logs)

        # ---------------------------------
        # Threat Intelligence
        # ---------------------------------

        context.threat_intel = self.enrichment_engine.enrich(
            context.ioc,
            context.software,
            context.metadata.event_type
        )

        # ---------------------------------
        # Risk
        # ---------------------------------

        context.risk = self.risk_engine.calculate(

            context.threat_intel,

            context.metadata.event_type,

            len(context.similar_logs)

        )

        # ---------------------------------
        # Confidence
        # ---------------------------------

        context.confidence = self.confidence_engine.calculate(

            context.threat_intel,

            context.average_similarity,

            len(context.similar_logs)

        )

        # ---------------------------------
        # LLM
        # ---------------------------------

        context.incident_report = self.chain.invoke({
            "current_log": context.raw_log,
            "retrieved_logs": "\n\n".join(
                result.document.log for result in context.similar_logs
            )
        })

        return context