"""Offline tests for the before/after metrics (rag-lab eval).

compute_metrics() is pure, so it is tested on hand-built findings. run_eval() is tested with the
pipeline stubbed to answer like a vulnerable model with SECURE_MODE off and a fixed one with it on.
"""

import json
from dataclasses import replace

import pytest
from typer.testing import CliRunner

from rag_attack_lab.attacks import metrics, runner
from rag_attack_lab.attacks.base import Detection, Finding
from rag_attack_lab.attacks.cases import BENIGN_CASES, CASES, CASES_BY_ID
from rag_attack_lab.attacks.metrics import (
    BenignResult,
    compute_metrics,
    contains_fact,
    run_benign,
    run_eval,
    write_metrics,
)
from rag_attack_lab.cli import app
from rag_attack_lab.ingest import ingest
from rag_attack_lab.rag import RagResult


def make_finding(case, triggered: bool, secure: bool = False) -> Finding:
    detection = Detection(triggered, "summary", ["evidence"] if triggered else [])
    return Finding(case, detection, case.question, "prompt", "answer", [], "fake/offline", "t", secure_mode=secure)


def make_benign(case, correct: bool, blocked: bool = False) -> BenignResult:
    return BenignResult(case, "answer", correct, blocked)


def test_benign_cases_have_unique_ids_and_expected_facts():
    assert len({case.id for case in BENIGN_CASES}) == len(BENIGN_CASES)
    assert all(case.expected for case in BENIGN_CASES)


def test_benign_expected_facts_are_in_the_public_documents(settings):
    public_text = " ".join(path.read_text(encoding="utf-8") for path in settings.data_dir.glob("*.txt")).lower()
    for case in BENIGN_CASES:
        assert any(expected.lower() in public_text for expected in case.expected), case.id


def test_compute_metrics_counts_before_and_after():
    before = [make_finding(case, True) for case in CASES]
    after = [make_finding(case, False, secure=True) for case in CASES]
    benign_before = [make_benign(case, True) for case in BENIGN_CASES]
    benign_after = [make_benign(case, index != 0, blocked=index == 0) for index, case in enumerate(BENIGN_CASES)]

    result = compute_metrics(before, after, benign_before, benign_after)

    totals_before, totals_after = result["totals"]["before"], result["totals"]["after"]
    assert totals_before["attacks_triggered"] == 4 and totals_before["attack_block_rate"] == 0.0
    assert totals_after["attacks_triggered"] == 0 and totals_after["attack_block_rate"] == 1.0
    assert totals_before["benign_accuracy"] == 1.0 and totals_before["benign_block_rate"] == 0.0
    n = len(BENIGN_CASES)
    assert totals_after["benign_correct"] == n - 1
    assert totals_after["benign_block_rate"] == round(1 / n, 3)
    assert [item["id"] for item in result["attacks"]] == [case.id for case in CASES]
    assert all(item["before"]["triggered"] and not item["after"]["triggered"] for item in result["attacks"])
    assert set(result["definitions"]) >= {"attack_block_rate", "benign_block_rate"}


def test_compute_metrics_reports_a_fix_that_did_not_hold():
    before = [make_finding(case, True) for case in CASES]
    after = [make_finding(case, case.id.startswith("LLM01"), secure=True) for case in CASES]

    result = compute_metrics(before, after, [], [])

    still_open = [item["id"] for item in result["attacks"] if item["after"]["triggered"]]
    assert still_open == ["LLM01-indirect-injection"]
    assert result["totals"]["after"]["attack_block_rate"] == 0.75


def test_compute_metrics_rejects_mismatched_cases():
    before = [make_finding(case, True) for case in CASES]
    with pytest.raises(ValueError):
        compute_metrics(before, before[:-1], [], [])
    with pytest.raises(ValueError):
        compute_metrics(before, before, [make_benign(BENIGN_CASES[0], True)], [])


def test_compute_metrics_keeps_the_answers_as_evidence():
    before = [make_finding(case, True) for case in CASES]
    result = compute_metrics(before, before, [], [])
    assert all("answer" in item["before"] and "raw_answer" in item["after"] for item in result["attacks"])


@pytest.mark.parametrize(
    ("answer", "expected", "found"),
    [
        ("You get 25 days.", "25", True),
        ("You get 250 days.", "25", False),
        ("Core hours start at 10:00.", "10", True),
        ("It costs 100 dollars.", "10", False),
        ("The plan is $49.", "$4", False),
        ("Two-year warranty.", "two-year", True),
    ],
)
def test_contains_fact_matches_whole_words(answer, expected, found):
    assert contains_fact(answer, expected) is found


def test_run_benign_scores_the_answer(monkeypatch, settings):
    case = BENIGN_CASES[0]  # vacation days: 25
    answers = {"right": "Full-time employees get 25 days.", "wrong": "I don't know."}
    for label, answer in answers.items():
        stub = RagResult(question=case.question, prompt="p", answer=answer, chunks=[])
        monkeypatch.setattr(metrics, "answer_question", lambda question, settings, stub=stub: stub)
        assert run_benign(case, settings).correct is (label == "right")


def test_run_benign_marks_an_output_check_as_a_block(monkeypatch, settings):
    stub = RagResult(question="q", prompt="p", answer="I can't share my instructions.", chunks=[], guardrails=["LLM08"])
    monkeypatch.setattr(metrics, "answer_question", lambda question, settings: stub)

    result = run_benign(BENIGN_CASES[0], settings)

    assert result.blocked and not result.correct


def test_run_eval_runs_both_modes_and_ignores_the_env_flag(monkeypatch, settings):
    def fake_answer(question, settings):
        leaked = "RAL-CANARY-DBPASS-ABCDEF123456" if not settings.secure_mode else "I don't know."
        return RagResult(question=question, prompt="p", answer=leaked, chunks=[], secure_mode=settings.secure_mode)

    monkeypatch.setattr(runner, "answer_question", fake_answer)
    monkeypatch.setattr(metrics, "answer_question", fake_answer)
    monkeypatch.setattr(runner, "load_canaries", lambda path: {})

    result = run_eval(replace(settings, secure_mode=True))

    canary = next(item for item in result["attacks"] if item["id"] == "LLM02-canary-exfiltration")
    assert canary["before"]["triggered"] is True
    assert canary["after"]["triggered"] is False
    assert result["totals"]["after"]["attacks_triggered"] == 0
    assert result["timestamp"]


def test_run_eval_end_to_end_offline(settings, tmp_path):
    # The real pipeline with the fake model: no attack can trigger, and the output is well formed.
    ingest(settings.data_dir, settings)

    result = run_eval(settings)
    path = write_metrics(result, tmp_path)

    data = json.loads(path.read_text(encoding="utf-8"))
    assert path.name == "metrics.json"
    assert len(data["attacks"]) == len(CASES)
    assert len(data["benign"]) == len(BENIGN_CASES)
    assert data["totals"]["after"]["attacks_triggered"] == 0


def test_eval_command_runs_both_modes_even_with_secure_mode_set(monkeypatch, settings, tmp_path):
    # The env says SECURE_MODE=true; eval must still produce a before run with it off.
    ingest(settings.data_dir, settings)
    monkeypatch.setenv("SECURE_MODE", "true")
    seen_modes = []
    real_run_mode = metrics.run_mode

    def recording_run_mode(mode_settings):
        seen_modes.append(mode_settings.secure_mode)
        return real_run_mode(mode_settings)

    monkeypatch.setattr("rag_attack_lab.cli.load_settings", lambda: replace(settings, secure_mode=True))
    monkeypatch.setattr(metrics, "run_mode", recording_run_mode)

    result = CliRunner().invoke(app, ["eval", "--out", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert seen_modes == [False, True]
    assert (tmp_path / "metrics.json").exists()


def test_attack_command_names_output_by_mode(monkeypatch, settings, tmp_path):
    ingest(settings.data_dir, settings)
    monkeypatch.setattr("rag_attack_lab.cli.load_settings", lambda: replace(settings, secure_mode=True))

    result = CliRunner().invoke(app, ["attack", "--out", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert (tmp_path / "retest.json").exists() and not (tmp_path / "findings.json").exists()


def test_attack_output_is_named_by_mode(settings, tmp_path):
    assert runner.default_name(settings) == "findings"
    assert runner.default_name(replace(settings, secure_mode=True)) == "retest"

    finding = make_finding(CASES_BY_ID["LLM09-rag-poisoning"], False, secure=True)
    json_path, md_path = runner.write_findings([finding], tmp_path, "retest")

    assert (json_path.name, md_path.name) == ("retest.json", "retest.md")
    markdown = md_path.read_text(encoding="utf-8")
    assert markdown.startswith("# Retest findings")
    assert "SECURE_MODE: on" in markdown


def test_wrote_lines_never_print_an_absolute_out_folder(monkeypatch, settings, tmp_path):
    ingest(settings.data_dir, settings)
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    monkeypatch.chdir(project)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setattr("rag_attack_lab.cli.load_settings", lambda: settings)
    outside = tmp_path / "private_folder"

    for command in (["attack"], ["eval"]):
        result = CliRunner().invoke(app, [*command, "--out", str(outside)])
        assert result.exit_code == 0, result.output
        wrote = [line for line in result.output.splitlines() if line.startswith("Wrote ")]
        assert wrote == ["Wrote <outside project>"]
        assert "private_folder" not in result.output
        assert str(tmp_path) not in result.output and tmp_path.as_posix() not in result.output

    inside = project / "out"
    result = CliRunner().invoke(app, ["attack", "--out", str(inside)])
    assert "Wrote out/findings.json, out/findings.md" in result.output
    result = CliRunner().invoke(app, ["eval", "--out", str(inside)])
    assert "Wrote out/metrics.json" in result.output
