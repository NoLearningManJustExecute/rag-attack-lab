"""Find the chunks most similar to a question."""

from dataclasses import dataclass

from rag_attack_lab.config import Settings
from rag_attack_lab.defenses import retrieval_filter
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
    # LLM02: with SECURE_MODE off there is no access-control filter. Any question can retrieve any
    # chunk, including internal documents and their canary secrets. There is no notion of who is asking.
    search_filter = None
    if settings.secure_mode:
        # LLM02 and LLM09 fix: the default caller has no clearance, so only public, unflagged chunks
        # are searched. Internal canaries and untrusted or poisoned documents never reach the prompt.
        search_filter = retrieval_filter()
    results = store.similarity_search_with_score(question, k=k or settings.top_k, filter=search_filter)
    return [
        RetrievedChunk(
            text=document.page_content,
            source=document.metadata.get("source", "unknown"),
            score=score,
            metadata=document.metadata,
        )
        for document, score in results
    ]


def flagged_texts(settings: Settings) -> list[str]:
    """The text of every chunk the ingest screen flagged as suspicious (the quarantine)."""
    return get_vector_store(settings).get(where={"suspicious": True}, include=["documents"])["documents"]
