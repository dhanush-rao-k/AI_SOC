from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
VECTORSTORE_DIR = BASE_DIR / "vectorstore"
VECTORSTORE_INDEX_DIR = VECTORSTORE_DIR / "index"

MODEL_NAME = "mistral"
EMBEDDING_MODEL = "nomic-embed-text"

TOP_K = 5
TEMPERATURE = 0.0
MAX_TOKENS = 512