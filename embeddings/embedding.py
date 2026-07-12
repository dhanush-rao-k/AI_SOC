from typing import List

from langchain_ollama import OllamaEmbeddings

from config import EMBEDDING_MODEL


class EmbeddingGenerator:
    """
    Generates embeddings using Ollama.
    """

    def __init__(self):

        self.embedding_model = OllamaEmbeddings(
            model=EMBEDDING_MODEL
        )

    def embed_query(self, text: str) -> List[float]:
        """
        Generates an embedding for a search query.
        """

        return self.embedding_model.embed_query(text)

    def embed_document(self, text: str) -> List[float]:
        """
        Generates an embedding for a document/log.
        """

        return self.embedding_model.embed_documents([text])[0]