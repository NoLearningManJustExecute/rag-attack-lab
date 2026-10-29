"""Preflight checks for `rag-lab doctor`: is the lab set up and ready to run?

Each check returns a CheckResult with a status of PASS, FAIL, or SKIP. Ollama is only
contacted when a provider is set to ollama, so the offline test setup (fake providers)
never needs a running model.
"""

import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from rag_attack_lab.config import Settings
from rag_attack_lab.vectorstore import get_vector_store

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

KNOWN_LLM_PROVIDERS = {"ollama", "anthropic", "fake"}
KNOWN_EMBEDDING_PROVIDERS = {"ollama", "fake"}
OLLAMA_TIMEOUT_SECONDS = 3


@dataclass
class CheckResult:
    name: str
    status: str
    detail: str


def check_providers(settings: Settings) -> CheckResult:
    """Fail if LLM_PROVIDER or EMBEDDING_PROVIDER is not a value the lab understands."""
    problems = []
    if settings.llm_provider not in KNOWN_LLM_PROVIDERS:
        problems.append(f"unknown LLM_PROVIDER {settings.llm_provider!r}")
    if settings.embedding_provider not in KNOWN_EMBEDDING_PROVIDERS:
        problems.append(f"unknown EMBEDDING_PROVIDER {settings.embedding_provider!r}")

    if problems:
        return CheckResult("Providers", FAIL, "; ".join(problems))
    return CheckResult("Providers", PASS, f"chat={settings.llm_provider}, embeddings={settings.embedding_provider}")


def list_ollama_models(base_url: str) -> list[str]:
    """Ask the Ollama server which models are pulled. Raises OSError if it can't be reached."""
    url = base_url.rstrip("/") + "/api/tags"
    with urllib.request.urlopen(url, timeout=OLLAMA_TIMEOUT_SECONDS) as response:
        body = json.load(response)
    return [model["name"] for model in body.get("models", [])]


def with_default_tag(model: str) -> str:
    """Ollama treats a model name without a tag as `:latest` (nomic-embed-text -> nomic-embed-text:latest)."""
    return model if ":" in model else f"{model}:latest"


def check_ollama_model(label: str, model: str, available: list[str]) -> CheckResult:
    """PASS if `model` is in the list of models Ollama has pulled."""
    if with_default_tag(model) in {with_default_tag(name) for name in available}:
        return CheckResult(label, PASS, model)
    return CheckResult(label, FAIL, f"{model} is not pulled. Run: ollama pull {model}")


def check_ollama(settings: Settings) -> list[CheckResult]:
    """Check that Ollama is reachable and has the configured models. Skipped if no provider uses Ollama."""
    needed = []
    if settings.llm_provider == "ollama":
        needed.append(("Ollama chat model", settings.ollama_chat_model))
    if settings.embedding_provider == "ollama":
        needed.append(("Ollama embedding model", settings.ollama_embed_model))

    if not needed:
        return [CheckResult("Ollama", SKIP, "no provider is set to ollama")]

    try:
        available = list_ollama_models(settings.ollama_base_url)
    except (OSError, ValueError) as error:
        # OSError covers connection errors and timeouts; ValueError covers a reply that isn't JSON.
        results = [CheckResult("Ollama reachable", FAIL, f"{settings.ollama_base_url}: {error}")]
        results += [CheckResult(label, SKIP, "Ollama is not reachable") for label, _ in needed]
        return results

    results = [CheckResult("Ollama reachable", PASS, settings.ollama_base_url)]
    results += [check_ollama_model(label, model, available) for label, model in needed]
    return results


OUTSIDE_PROJECT = "<outside project>"


def project_root() -> Path:
    """The repository the CLI runs in: the nearest folder at or above the working directory that
    holds a pyproject.toml or a .git entry, else the working directory itself."""
    cwd = Path.cwd().resolve()
    for folder in (cwd, *cwd.parents):
        if (folder / "pyproject.toml").is_file() or (folder / ".git").exists():
            return folder
    return cwd


def shown_path(path: Path) -> str:
    """A path as the CLI prints it: relative to the repository, or withheld entirely.

    CLI output ends up in screenshots and logs, so it never shows an absolute local path. A path
    outside the repository shows no part of itself, since any folder or file name in it could be a
    user name.
    """
    try:
        return path.resolve().relative_to(project_root()).as_posix()
    except ValueError:
        return OUTSIDE_PROJECT


def check_vector_store(settings: Settings) -> CheckResult:
    """Check that the Chroma store exists on disk and holds at least one chunk."""
    if not settings.chroma_dir.exists():
        location = shown_path(settings.chroma_dir)
        return CheckResult("Chroma store", FAIL, f"{location} does not exist. Run: rag-lab ingest")

    chunk_count = len(get_vector_store(settings).get()["ids"])
    location = f"{shown_path(settings.chroma_dir)} (collection {settings.chroma_collection!r})"
    if chunk_count == 0:
        return CheckResult("Chroma store", FAIL, f"{location} is empty. Run: rag-lab ingest")
    return CheckResult("Chroma store", PASS, f"{location}: {chunk_count} chunks")


def run_checks(settings: Settings) -> list[CheckResult]:
    """Run every check, in the order they are shown."""
    return [check_providers(settings), *check_ollama(settings), check_vector_store(settings)]
