from dataclasses import asdict, dataclass, field
from pathlib import Path
import pickle
from typing import Any

from config import VECTORSTORE_INDEX_DIR


@dataclass
class DocumentRecord:
    document_id: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)


def save_document_store(
    records: list[DocumentRecord],
    path: Path | str = VECTORSTORE_INDEX_DIR / "metadata.pkl",
) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as handle:
        pickle.dump([asdict(record) for record in records], handle)
    return target


def load_document_store(path: Path | str = VECTORSTORE_INDEX_DIR / "metadata.pkl") -> list[DocumentRecord]:
    target = Path(path)
    if not target.exists() or target.stat().st_size == 0:
        return []
    with target.open("rb") as handle:
        payload = pickle.load(handle)
    return [DocumentRecord(**item) for item in payload]