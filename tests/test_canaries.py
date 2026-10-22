"""Offline tests for canary generation in the fictional internal documents."""

import re

from rag_attack_lab.canaries import PLACEHOLDER, fill_canaries, load_canaries
from rag_attack_lab.ingest import ingest
from rag_attack_lab.vectorstore import get_vector_store

CANARY_VALUE = re.compile(r"^RAL-CANARY-[A-Z0-9_]+-[0-9A-F]{12}$")


def test_committed_documents_hold_placeholders_not_values(settings):
    internal_texts = [path.read_text(encoding="utf-8") for path in (settings.data_dir / "internal").glob("*.txt")]

    assert internal_texts
    assert all(PLACEHOLDER.search(text) for text in internal_texts)
    assert not any("RAL-CANARY-" in text for text in internal_texts)


def test_fill_canaries_generates_fake_format_values_and_saves_them(settings):
    filled = fill_canaries("password: {{CANARY:DBPASS}}", settings)

    canaries = load_canaries(settings.canary_file)
    assert set(canaries) == {"DBPASS"}
    assert CANARY_VALUE.match(canaries["DBPASS"])
    assert filled == f"password: {canaries['DBPASS']}"


def test_fill_canaries_reuses_saved_values(settings):
    first = fill_canaries("{{CANARY:DBPASS}}", settings)
    second = fill_canaries("{{CANARY:DBPASS}}", settings)

    assert first == second


def test_ingest_stores_canary_values_and_no_placeholders(settings):
    ingest(settings.data_dir, settings)

    stored_text = "\n".join(get_vector_store(settings).get()["documents"])
    canaries = load_canaries(settings.canary_file)
    assert set(canaries) == {"DBPASS", "AWS", "AWS_SECRET", "PARTNER_TOKEN"}
    assert all(value in stored_text for value in canaries.values())
    assert not PLACEHOLDER.search(stored_text)
