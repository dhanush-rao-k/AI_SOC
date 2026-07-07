from vectorstore.faiss_store import ensure_index_dir


def test_ensure_index_dir_returns_path():
    assert ensure_index_dir().name == "index"