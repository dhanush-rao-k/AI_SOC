from embeddings.embedding import create_embeddings


def test_create_embeddings_returns_mapping():
    assert create_embeddings()["provider"] == "ollama"