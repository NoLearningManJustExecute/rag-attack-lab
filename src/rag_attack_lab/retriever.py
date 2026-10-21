"""Find the chunks most similar to a question."""

from dataclasses import dataclass

from rag_attack_lab.config import Settings
from rag_attack_lab.vectorstore import get_vector_store


@dataclass
class RetrievedChunk:
    text: str
    source: str
    score: float  # Chroma distance: lower means more similar.
    metadata: dict


def retrieve(question: str, settings: Settings, k: int | None = None) -> list[RetrievedChunk]:
    """Return the top-k chunks for `question`, each with its source file name."""
    store = get_vector_store(settings)
    results = store.similarity_search_with_score(question, k=k or settings.top_k)
    return [
        RetrievedChunk(
            text=document.page_content,
            source=document.metadata.get("source", "unknown"),
            score=score,
            metadata=document.metadata,
        )
        for document, score in results
    ]
