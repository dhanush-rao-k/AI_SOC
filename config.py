"""
Global configuration for the AI SOC.
"""

# ---------- LLM ---------- #

LLM_MODEL = "mistral"

LLM_TEMPERATURE = 0.0

MAX_TOKENS = 512


# ---------- Embeddings ---------- #

EMBEDDING_MODEL = "nomic-embed-text"


# ---------- Vector Store ---------- #

FAISS_INDEX_PATH = "data/faiss.index"

DOCUMENT_STORE_PATH = "data/documents.pkl"


TOP_K = 20

FINAL_RESULTS = 5


# ---------- Threat Intelligence ---------- #

VIRUSTOTAL_API_KEY = ""


# ---------- Risk Engine ---------- #

MAX_RISK_SCORE = 100