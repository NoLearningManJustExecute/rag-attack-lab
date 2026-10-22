"""Shared test fixtures. Every test runs offline with the fake chat model and fake embeddings."""

from dataclasses import replace
from pathlib import Path

import pytest

from rag_attack_lab.config import load_settings

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"


@pytest.fixture
def settings(tmp_path):
    """Offline settings with a throwaway Chroma folder and canary file for each test."""
    return replace(
        load_settings(),
        llm_provider="fake",
        embedding_provider="fake",
        chroma_dir=tmp_path / "chroma_db",
        chroma_collection="test_collection",
        data_dir=DATA_DIR,
        canary_file=tmp_path / ".canaries",
        chunk_size=400,
        chunk_overlap=50,
        top_k=3,
    )
