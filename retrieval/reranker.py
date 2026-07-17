from typing import List

from models.context import AnalysisContext
from vectorstore.faiss_store import SearchResult
from vectorstore.faiss_store import SecurityDocument
from retrieval.scorer import CorrelationScorer


class ReRanker:

    def __init__(self):

        self.scorer = CorrelationScorer()

    def rerank(

        self,

        query_document: AnalysisContext,

        candidates: list[SearchResult],

        top_k: int = 5

    ) -> List[SearchResult]:

        ranked = []

        for candidate in candidates:

            score = self.scorer.score(

                query_document,

                candidate.document,

                candidate.similarity

            )

            ranked.append(

                (

                    score,

                    candidate

                )

            )

        ranked.sort(

            key=lambda x: x[0],

            reverse=True

        )

        return [

            candidate

            for score, candidate

            in ranked[:top_k]

        ]