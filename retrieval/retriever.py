from typing import List

from models.context import AnalysisContext
from retrieval.reranker import ReRanker
from vectorstore.faiss_store import SearchResult


class HybridRetriever:

    def __init__(self, vector_store):

        self.vector_store = vector_store

        self.reranker = ReRanker()

    def retrieve(

        self,

        query_document: AnalysisContext,

        semantic_k: int = 20,

        final_k: int = 5

    ) -> List[SearchResult]:

        candidates = self.vector_store.search(

            query_document.raw_log,

            semantic_k

        )

        return self.reranker.rerank(

            query_document,

            candidates,

            final_k

        )