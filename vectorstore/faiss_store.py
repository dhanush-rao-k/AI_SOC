from pathlib import Path
import pickle
from typing import Any

from config import VECTORSTORE_INDEX_DIR


def ensure_index_dir(index_dir: Path | str = VECTORSTORE_INDEX_DIR) -> Path:
    path = Path(index_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_faiss_index(index: Any, path: Path | str = VECTORSTORE_INDEX_DIR / "faiss.index") -> Path:
    target = Path(path)
    ensure_index_dir(target.parent)
    with target.open("wb") as handle:
        pickle.dump(index, handle)
    return target


def load_faiss_index(path: Path | str = VECTORSTORE_INDEX_DIR / "faiss.index") -> Any:
    target = Path(path)
    if not target.exists() or target.stat().st_size == 0:
        return None
    with target.open("rb") as handle:
        return pickle.load(handle)