import os
import pickle
from dataclasses import dataclass
from typing import Dict, List, Optional

import faiss
import numpy as np

from config import (
    DOCUMENT_STORE_PATH,
    FAISS_INDEX_PATH,
)

from embeddings.embedding import EmbeddingGenerator
from ingestion.metadata import Metadata


# -------------------------------------------------
# Data Classes
# -------------------------------------------------

@dataclass
class SecurityDocument:
    """
    Represents one security log stored in the vector database.
    """

    document_id: int

    log: str

    metadata: Metadata


@dataclass
class SearchResult:
    """
    Represents one retrieved result from FAISS.
    """

    similarity: float

    document: SecurityDocument


# -------------------------------------------------
# Vector Store
# -------------------------------------------------

class FAISSStore:

    def __init__(self):

        self.embedding_generator = EmbeddingGenerator()

        self.documents: Dict[int, SecurityDocument] = {}

        self.next_document_id = 0

        self.initialize()

    # -------------------------------------------------

    def initialize(self):

        """
        Creates an empty FAISS index.
        """

        if self.index_exists():

            return

        dimension = len(
            self.embedding_generator.embed_query(
                "initialize"
            )
        )

        self.index = faiss.IndexFlatIP(dimension)

    # -------------------------------------------------

    def index_exists(self):

        return hasattr(self, "index") and self.index is not None

    # -------------------------------------------------

    def add_document(
        self,
        log: str,
        metadata: Metadata
    ):

        embedding = self.embedding_generator.embed_document(log)

        vector = np.array(
            embedding,
            dtype=np.float32
        ).reshape(1, -1)

        faiss.normalize_L2(vector)

        self.index.add(vector)

        document = SecurityDocument(

            document_id=self.next_document_id,

            log=log,

            metadata=metadata

        )

        self.documents[
            self.next_document_id
        ] = document

        self.next_document_id += 1

    # -------------------------------------------------

    def search(
        self,
        query: str,
        k: int = 5
    ) -> List[SearchResult]:

        if self.count() == 0:
            return []

        k = min(k, self.count())

        embedding = self.embedding_generator.embed_query(query)

        vector = np.array(
            embedding,
            dtype=np.float32
        ).reshape(1, -1)

        faiss.normalize_L2(vector)

        similarities, indices = self.index.search(
            vector,
            k
        )

        results = []

        for similarity, index in zip(
            similarities[0],
            indices[0]
        ):

            if index == -1:
                continue

            results.append(

                SearchResult(

                    similarity=float(similarity),

                    document=self.documents[index]

                )

            )

        return results

    # -------------------------------------------------

    def get_document(
        self,
        document_id: int
    ) -> Optional[SecurityDocument]:

        return self.documents.get(document_id)

    # -------------------------------------------------

    def count(self):

        return self.index.ntotal

    # -------------------------------------------------

    def save(self):

        os.makedirs(

            os.path.dirname(
                FAISS_INDEX_PATH
            ),

            exist_ok=True

        )

        faiss.write_index(

            self.index,

            FAISS_INDEX_PATH

        )

        with open(

            DOCUMENT_STORE_PATH,

            "wb"

        ) as file:

            pickle.dump(

                {

                    "documents": self.documents,

                    "next_document_id": self.next_document_id

                },

                file

            )

    # -------------------------------------------------

    def load(self):

        if not os.path.exists(FAISS_INDEX_PATH):

            self.initialize()

            return

        if not os.path.exists(DOCUMENT_STORE_PATH):

            self.initialize()

            return

        self.index = faiss.read_index(
            FAISS_INDEX_PATH
        )

        with open(
            DOCUMENT_STORE_PATH,
            "rb"
        ) as file:

            data = pickle.load(file)

        self.documents = data["documents"]

        self.next_document_id = data["next_document_id"]