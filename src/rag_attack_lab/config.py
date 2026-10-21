"""Settings for the lab, read from environment variables (and an optional .env file).

Every setting has a default here, and every setting is listed in .env.example.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    llm_provider: str
    ollama_base_url: str
    ollama_chat_model: str
    anthropic_model: str
    embedding_provider: str
    ollama_embed_model: str
    chroma_dir: Path
    chroma_collection: str
    data_dir: Path
    chunk_size: int
    chunk_overlap: int
    top_k: int
    llm_temperature: float


def load_settings() -> Settings:
    """Build Settings from the environment. Values in .env are loaded first if the file exists."""
    load_dotenv()
    return Settings(
        llm_provider=os.getenv("LLM_PROVIDER", "ollama").lower(),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        ollama_chat_model=os.getenv("OLLAMA_CHAT_MODEL", "llama3.1:8b"),
        anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5"),
        embedding_provider=os.getenv("EMBEDDING_PROVIDER", "ollama").lower(),
        ollama_embed_model=os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text"),
        chroma_dir=Path(os.getenv("CHROMA_DIR", "chroma_db")),
        chroma_collection=os.getenv("CHROMA_COLLECTION", "rag_attack_lab"),
        data_dir=Path(os.getenv("DATA_DIR", "data")),
        chunk_size=int(os.getenv("CHUNK_SIZE", "800")),
        chunk_overlap=int(os.getenv("CHUNK_OVERLAP", "100")),
        top_k=int(os.getenv("TOP_K", "4")),
        llm_temperature=float(os.getenv("LLM_TEMPERATURE", "0")),
    )
