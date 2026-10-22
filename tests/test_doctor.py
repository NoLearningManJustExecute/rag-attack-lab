"""Offline tests for `rag-lab doctor`. Ollama is never contacted: calls to it are replaced in each test."""

from dataclasses import replace

import pytest
from typer.testing import CliRunner

from rag_attack_lab import doctor
from rag_attack_lab.cli import app
from rag_attack_lab.doctor import FAIL, PASS, SKIP, check_ollama, check_providers, check_vector_store
from rag_attack_lab.ingest import ingest


@pytest.fixture
def no_ollama(monkeypatch):
    """Make any attempt to contact Ollama fail the test."""

    def fail_if_called(base_url):
        raise AssertionError("doctor contacted Ollama, but no provider is set to ollama")

    monkeypatch.setattr(doctor, "list_ollama_models", fail_if_called)


def test_ollama_checks_are_skipped_with_fake_providers(settings, no_ollama):
    results = check_ollama(settings)

    assert [result.status for result in results] == [SKIP]


def test_ollama_models_present(settings, monkeypatch):
    settings = replace(
        settings,
        llm_provider="ollama",
        embedding_provider="ollama",
        ollama_chat_model="llama3.1:8b",
        ollama_embed_model="nomic-embed-text",
    )
    # Ollama lists untagged pulls as ":latest", so "nomic-embed-text" should match "nomic-embed-text:latest".
    monkeypatch.setattr(doctor, "list_ollama_models", lambda base_url: ["llama3.1:8b", "nomic-embed-text:latest"])

    results = check_ollama(settings)

    assert [(result.name, result.status) for result in results] == [
        ("Ollama reachable", PASS),
        ("Ollama chat model", PASS),
        ("Ollama embedding model", PASS),
    ]


def test_ollama_model_missing(settings, monkeypatch):
    settings = replace(settings, llm_provider="ollama", ollama_chat_model="llama3.1:8b")
    monkeypatch.setattr(doctor, "list_ollama_models", lambda base_url: ["nomic-embed-text:latest"])

    results = check_ollama(settings)

    assert results[-1].status == FAIL
    assert "ollama pull llama3.1:8b" in results[-1].detail


def test_ollama_unreachable(settings, monkeypatch):
    settings = replace(settings, llm_provider="ollama")

    def refuse(base_url):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(doctor, "list_ollama_models", refuse)

    results = check_ollama(settings)

    assert [(result.name, result.status) for result in results] == [
        ("Ollama reachable", FAIL),
        ("Ollama chat model", SKIP),
    ]


def test_unknown_provider_fails(settings):
    result = check_providers(replace(settings, llm_provider="nonsense"))

    assert result.status == FAIL
    assert "nonsense" in result.detail


def test_missing_store_fails(settings):
    result = check_vector_store(settings)

    assert result.status == FAIL
    assert not settings.chroma_dir.exists(), "the check must not create the store"


def test_store_reports_chunk_count(settings):
    chunks = ingest(settings.data_dir, settings)

    result = check_vector_store(settings)

    assert result.status == PASS
    assert f"{len(chunks)} chunks" in result.detail


def test_doctor_command_exit_code(settings, monkeypatch, no_ollama):
    for name, value in {
        "LLM_PROVIDER": "fake",
        "EMBEDDING_PROVIDER": "fake",
        "CHROMA_DIR": str(settings.chroma_dir),
        "CHROMA_COLLECTION": settings.chroma_collection,
    }.items():
        monkeypatch.setenv(name, value)
    runner = CliRunner()

    before_ingest = runner.invoke(app, ["doctor"])
    ingest(settings.data_dir, settings)
    after_ingest = runner.invoke(app, ["doctor"])

    assert before_ingest.exit_code == 1, before_ingest.output
    assert after_ingest.exit_code == 0, after_ingest.output
    assert "All checks passed." in after_ingest.output
