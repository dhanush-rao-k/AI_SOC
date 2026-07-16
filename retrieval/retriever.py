from retrieval.reranker import ReRanker


class HybridRetriever:

    def __init__(self, vector_store):

        self.vector_store = vector_store

        self.reranker = ReRanker()

    def retrieve(

        self,

        query_document,

        semantic_k=20,

        final_k=5

    ):

        candidates = self.vector_store.search(

            query_document.log,

            semantic_k

        )

        return self.reranker.rerank(

            query_document,

            candidates,

            final_k

        )