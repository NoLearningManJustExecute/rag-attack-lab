# Roadmap

RAG Attack Lab is built in phases. Each phase ends with working, tested code and a tagged release.
The full loop is the point: build a vulnerable target, attack it, fix it, and measure the result.

Status key: Done / In progress / Planned

| Version | Phase | Status |
|---|---|---|
| v0.1 | Clean RAG baseline | Done |
| v1.0 | Documented vulnerable target | Done |
| v1.1 | Minimal web UI | Planned |
| v2.0 | Attack and findings | Done |
| v3.0 | Fix and measured retest | Done |
| v4.0 | Automated red-team checks in CI | Planned |
| v5.0 | Pentest report and publication | Planned |

## v0.1 — Clean RAG baseline (Done)

A working retrieval-augmented generation pipeline with no deliberate weaknesses. This is the known-good reference point.

- Local LLM through Ollama (llama3.1:8b by default), optional Anthropic provider
- Local embeddings (nomic-embed-text) and ChromaDB vector store
- TXT and PDF ingestion, top-k retrieval with source metadata
- CLI: `ingest`, `ask` (with `--show-prompt`), `reset`
- Offline test suite using a deterministic fake provider and fake embeddings
- All configuration from environment variables

## v1.0 — Documented vulnerable target (Done)

The baseline is changed on purpose so it can be attacked in later phases. Every weakness is documented and tagged with its framework IDs.

- Weaknesses mapped to the OWASP Top 10 for LLM Applications (2026): LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM08 Hidden Context Exposure, LLM09 Vector and Embedding Weaknesses
- Each weakness also mapped to MITRE ATLAS techniques
- Fictional sensitive documents that use generated canary values, so nothing in the repo looks like a real credential
- `VULNERABILITIES.md`: each weakness, where it lives in the code, why it exists, and what would have prevented it
- Threat model in `docs/`
- Tests that confirm each weakness is present
- Housekeeping: idempotent ingest, `.gitattributes`, a `doctor` preflight command

## v1.1 — Minimal web UI (Planned)

- A small local web interface, bound to 127.0.0.1 only
- Adds a rendering surface so output-handling risks (OWASP LLM10) can be studied

## v2.0 — Attack and findings (Done)

- Test the lab's own weaknesses, and only this lab
- Every finding records evidence, impact, and severity
- Findings show real impact, not cosmetic model behavior
- `rag-lab attack` runs the four cases; a real run against llama3.1:8b triggered all four (`findings/`)

## v3.0 — Fix and measured retest (Done)

- Fix each finding, behind a `SECURE_MODE` flag so one harness shows the before and the after (done)
- Evaluation runner that outputs JSON metrics before and after the fixes: attack-block rate, benign-block rate (false positives), and accuracy (done: `rag-lab eval` writes `findings/metrics.json`)
- Retest evidence committed: 4/4 attacks triggered before, 0/4 after, and 8/8 benign questions still answered (done:
  `findings/retest.md`)
- Ingest-time checks for suspicious documents, with the ability to purge and rebuild the index (done: flagged and
  untrusted documents are quarantined from retrieval; `reset` then `ingest` rebuilds the index)
- New tests confirm each fix in secure mode, while the v1.0 weakness tests keep passing in the default mode (done)

## v4.0 — Automated red-team checks in CI (Planned)

- Run the evaluation on every push in GitHub Actions
- Uses the offline fake provider so CI needs no model and no secrets
- Tool choice (promptfoo, garak, or PyRIT) made after comparing current versions

## v5.0 — Pentest report and publication (Planned)

- PDF report: executive summary, scope, methodology, findings with severity and evidence, remediation, retest results
- Two-minute demo video or GIF
- Write-up and public release

## Scope and ethics

Everything runs locally against this lab only, with fictional data. Nothing in this project targets real systems.
