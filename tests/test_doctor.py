"""Offline tests for `rag-lab doctor`. Ollama is never contacted: calls to it are replaced in each test."""

from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rag_attack_lab import doctor
from rag_attack_lab.cli import app
from rag_attack_lab.doctor import FAIL, PASS, SKIP, check_ollama, check_providers, check_vector_store, shown_path
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


def test_doctor_never_prints_absolute_paths(settings, monkeypatch, no_ollama, tmp_path):
    project = tmp_path / "project"
    (project / "data").mkdir(parents=True)
    monkeypatch.chdir(project)
    assert shown_path(project / "data" / "x.txt") == "data/x.txt"
    assert shown_path(tmp_path / "elsewhere" / "store") == "<outside project>"

    for name, value in {
        "LLM_PROVIDER": "fake",
        "EMBEDDING_PROVIDER": "fake",
        "CHROMA_DIR": str(settings.chroma_dir),
        "DATA_DIR": str(project / "data"),
        # Wide enough that Rich never wraps or truncates a path, so a leak would show in full.
        "COLUMNS": "400",
    }.items():
        monkeypatch.setenv(name, value)
    output = CliRunner().invoke(app, ["doctor"]).output
    lines = output.splitlines()

    settings_rows = [line for line in lines if "chroma_dir" in line or "data_dir" in line]
    assert any("chroma_dir" in row and "<outside project>" in row for row in settings_rows)
    assert any("data_dir" in row and " data " in row for row in settings_rows)
    store_rows = [line for line in lines if "Chroma store" in line]
    assert store_rows and all("<outside project>" in row for row in store_rows)
    assert "chroma_db" not in "".join(store_rows)
    assert str(tmp_path) not in output
    assert tmp_path.as_posix() not in output


def test_shown_path_is_relative_to_the_repository_root(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / "src" / "pkg").mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    monkeypatch.chdir(repo / "src" / "pkg")
    assert shown_path(repo / "findings" / "x.json") == "findings/x.json"
    assert shown_path(Path("local.txt")) == "src/pkg/local.txt"
    assert shown_path(tmp_path / "private_folder" / "y.json") == "<outside project>"

    loose = tmp_path / "loose"
    loose.mkdir()
    monkeypatch.chdir(loose)
    assert shown_path(loose / "a" / "b.txt") == "a/b.txt"
