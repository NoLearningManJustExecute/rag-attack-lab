"""promptfoo provider that drives the RAG pipeline fully offline.

promptfoo calls `call_api` once per test case. The pipeline runs with the fake
chat provider and the deterministic hashing embeddings, so every run is the same
and needs no model, no network, and no secrets. That makes it safe to gate CI on.

The provider returns the assembled prompt (retrieved context plus the question)
as its output, so assertions in promptfooconfig.yaml can check that the pipeline
retrieves the right document and grounds the prompt in it. When real attack cases
are added in later milestones, they assert against this same provider.
"""

import atexit
import dataclasses
import shutil
import tempfile
from pathlib import Path

from rag_attack_lab.config import load_settings
from rag_attack_lab.ingest import ingest
from rag_attack_lab.rag import answer_question

# The repository's seed documents, regardless of where promptfoo is run from.
_DATA_DIR = Path(__file__).resolve().parents[2] / "data"

_settings = None


def _get_settings():
    """Ingest the seed documents once into a throwaway store and reuse it."""
    global _settings
    if _settings is not None:
        return _settings

    tmp_dir = tempfile.mkdtemp(prefix="promptfoo-chroma-")
    atexit.register(shutil.rmtree, tmp_dir, ignore_errors=True)

    _settings = dataclasses.replace(
        load_settings(),
        llm_provider="fake",
        embedding_provider="fake",
        data_dir=_DATA_DIR,
        chroma_dir=Path(tmp_dir),
        chroma_collection="promptfoo",
    )
    ingest(_DATA_DIR, _settings)
    return _settings


def call_api(prompt, options=None, context=None):
    """Answer `prompt` (the test's query) and return the assembled prompt for assertions."""
    settings = _get_settings()
    result = answer_question(prompt, settings)
    sources = sorted({chunk.source for chunk in result.chunks})
    return {
        "output": result.prompt,
        "metadata": {
            "answer": result.answer,
            "sources": sources,
            "num_chunks": len(result.chunks),
        },
    }
