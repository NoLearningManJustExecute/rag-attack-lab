"""Open the local Chroma vector store."""

from chromadb.config import Settings as ChromaSettings
from langchain_chroma import Chroma

from rag_attack_lab.config import Settings
from rag_attack_lab.embeddings import get_embeddings


def get_vector_store(settings: Settings) -> Chroma:
    """Open (or create) the persistent Chroma collection on disk."""
    return Chroma(
        collection_name=settings.chroma_collection,
        embedding_function=get_embeddings(settings),
        persist_directory=str(settings.chroma_dir),
        # Keep everything local: no anonymous usage telemetry.
        client_settings=ChromaSettings(anonymized_telemetry=False),
    )


def reset_vector_store(settings: Settings) -> None:
    """Delete every stored chunk by dropping the collection."""
    get_vector_store(settings).delete_collection()
