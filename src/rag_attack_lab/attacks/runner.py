"""Run attack cases against the configured model and write findings for the report."""

import json
from datetime import UTC, datetime
from pathlib import Path

from rag_attack_lab.attacks.base import AttackCase, Finding
from rag_attack_lab.attacks.cases import CASES
from rag_attack_lab.canaries import load_canaries
from rag_attack_lab.config import Settings
from rag_attack_lab.providers import describe_model
from rag_attack_lab.rag import answer_question


def run_attack(case: AttackCase, settings: Settings) -> Finding:
    """Run one case end to end and return the finding."""
    result = answer_question(case.question, settings)
    canaries = load_canaries(settings.canary_file)
    detection = case.detector(result, canaries)
    retrieved = [
        {"source": chunk.source, "chunk": chunk.metadata.get("chunk"), "score": round(chunk.score, 4)}
        for chunk in result.chunks
    ]
    return Finding(
        case=case,
        detection=detection,
        question=result.question,
        prompt=result.prompt,
        answer=result.answer,
        retrieved=retrieved,
        model=describe_model(settings),
        timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
    )


def run_all(settings: Settings, cases: list[AttackCase] | None = None) -> list[Finding]:
    """Run every case (or a given subset) and return the findings."""
    return [run_attack(case, settings) for case in (cases or CASES)]


def render_markdown(findings: list[Finding]) -> str:
    """Render findings as report-ready markdown: a summary table, then one section each."""
    model = findings[0].model if findings else "unknown"
    stamp = findings[0].timestamp if findings else ""
    lines = ["# Attack findings", "", f"Model: {model}", f"Run: {stamp}", ""]

    lines += ["| Case | OWASP | Severity | Result |", "| --- | --- | --- | --- |"]
    for finding in findings:
        verdict = "VULNERABLE" if finding.triggered else "not triggered"
        lines.append(f"| {finding.case.id} | {finding.case.owasp_id} | {finding.case.severity} | {verdict} |")
    lines.append("")

    for finding in findings:
        verdict = "VULNERABLE" if finding.triggered else "not triggered"
        lines += [
            f"## {finding.case.id} - {finding.case.title}",
            "",
            f"- OWASP: {finding.case.owasp_id}",
            f"- MITRE ATLAS: {finding.case.atlas_technique}",
            f"- Severity: {finding.case.severity}",
            f"- Result: {verdict}",
            f"- Detector: {finding.detection.summary}",
        ]
        if finding.detection.evidence:
            lines.append(f"- Evidence: {', '.join(finding.detection.evidence)}")
        lines += [
            f"- Target document retrieved: {'yes' if finding.detection.retrieved_target else 'no'}",
            "",
            f"Why it works: {finding.case.rationale}",
            "",
            f"Impact: {finding.case.impact}",
            "",
            f"Remediation: {finding.case.remediation}",
            "",
            "Question sent:",
            "",
            "```",
            finding.question,
            "```",
            "",
            "Model answer:",
            "",
            "```",
            finding.answer,
            "```",
            "",
        ]
        sources = ", ".join(f"{item['source']}#{item['chunk']}" for item in finding.retrieved) or "(none)"
        lines += [f"Retrieved: {sources}", ""]

    return "\n".join(lines).rstrip() + "\n"


def write_findings(findings: list[Finding], out_dir: Path) -> list[Path]:
    """Write findings.json (machine-readable) and findings.md (report-ready)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "findings.json"
    md_path = out_dir / "findings.md"
    json_path.write_text(json.dumps([finding.to_dict() for finding in findings], indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(findings), encoding="utf-8")
    return [json_path, md_path]
