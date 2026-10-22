"""Data types for the attack harness: a case, a detection result, and a finding."""

from collections.abc import Callable
from dataclasses import dataclass, field

from rag_attack_lab.rag import RagResult


@dataclass(frozen=True)
class Detection:
    """The outcome of one detector run against one model response."""

    triggered: bool
    summary: str
    evidence: list[str] = field(default_factory=list)
    retrieved_target: bool = False


# A detector reads the pipeline result and the known canary values (used only by the
# LLM02 detector) and decides whether the attack succeeded. It is pure: no side effects.
Detector = Callable[[RagResult, dict[str, str]], Detection]


@dataclass(frozen=True)
class AttackCase:
    """One attack: the question to send and everything needed to report the result."""

    id: str
    owasp_id: str
    atlas_technique: str
    title: str
    severity: str
    question: str
    rationale: str
    impact: str
    remediation: str
    detector: Detector


@dataclass(frozen=True)
class BenignCase:
    """An ordinary question with a known answer, to measure what the fixes cost normal users."""

    id: str
    question: str
    expected: tuple[str, ...]  # the answer is correct if it contains any of these (case-insensitive)


@dataclass
class Finding:
    """The result of running one case: the case, the detection, and the captured evidence."""

    case: AttackCase
    detection: Detection
    question: str
    prompt: str
    answer: str
    retrieved: list[dict]
    model: str
    timestamp: str
    secure_mode: bool = False
    raw_answer: str = ""  # the model's own answer before any output check (same as answer when none fired)
    guardrails: list[str] = field(default_factory=list)

    @property
    def triggered(self) -> bool:
        return self.detection.triggered

    def to_dict(self) -> dict:
        """A JSON-friendly view, flattening the case metadata for the report."""
        return {
            "id": self.case.id,
            "title": self.case.title,
            "owasp": self.case.owasp_id,
            "atlas": self.case.atlas_technique,
            "severity": self.case.severity,
            "triggered": self.detection.triggered,
            "summary": self.detection.summary,
            "evidence": self.detection.evidence,
            "retrieved_target": self.detection.retrieved_target,
            "rationale": self.case.rationale,
            "impact": self.case.impact,
            "remediation": self.case.remediation,
            "question": self.question,
            "prompt": self.prompt,
            "answer": self.answer,
            "retrieved": self.retrieved,
            "model": self.model,
            "timestamp": self.timestamp,
            "secure_mode": self.secure_mode,
            "raw_answer": self.raw_answer,
            "guardrails": self.guardrails,
        }
