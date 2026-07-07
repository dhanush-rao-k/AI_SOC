from config import EMBEDDING_MODEL


def create_embeddings(model: str = EMBEDDING_MODEL) -> dict:
    return {"provider": "ollama", "model": model}