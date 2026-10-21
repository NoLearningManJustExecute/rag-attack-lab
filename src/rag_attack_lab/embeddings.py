"""Embedding providers.

- ollama: nomic-embed-text served by Ollama (the default).
- fake: a deterministic, offline bag-of-words embedding for tests.
"""

import hashlib
import math
import re

from langchain_core.embeddings import Embeddings

from rag_attack_lab.config import Settings


class HashingEmbeddings(Embeddings):
    """A tiny offline embedding: each word is hashed into one of `size` buckets.

    Texts that share words get similar vectors, so retrieval tests behave sensibly
    without a model. It is deterministic: the same text always gives the same vector.
    """

    def __init__(self, size: int = 256):
        self.size = size

    def _embed(self, text: str) -> list[float]:
        vector = [0.0] * self.size
        for word in re.findall(r"[a-z0-9]+", text.lower()):
            bucket = int(hashlib.md5(word.encode("utf-8")).hexdigest(), 16) % self.size
            vector[bucket] += 1.0
        length = math.sqrt(sum(value * value for value in vector)) or 1.0
        return [value / length for value in vector]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)


def get_embeddings(settings: Settings) -> Embeddings:
    """Return the embedding model selected by settings.embedding_provider."""
    provider = settings.embedding_provider

    if provider == "ollama":
        from langchain_ollama import OllamaEmbeddings

        return OllamaEmbeddings(model=settings.ollama_embed_model, base_url=settings.ollama_base_url)

    if provider == "fake":
        return HashingEmbeddings()

    raise ValueError(f"Unknown EMBEDDING_PROVIDER: {provider!r}. Use ollama or fake.")
