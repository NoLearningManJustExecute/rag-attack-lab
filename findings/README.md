# Findings

This folder holds the output of the attack harness (`rag-lab attack` and `rag-lab eval`).

- `findings.json` and `findings.md` - the before: a run with `SECURE_MODE` off (the
  default). One entry per attack case, with the verdict, evidence, the question sent,
  the model answer, and the retrieved sources. The markdown is report-ready: a summary
  table and one section per case with OWASP ID, MITRE ATLAS technique, severity,
  impact, and remediation. This feeds the pentest report (see `docs/report/`).
- `retest.json` and `retest.md` - the after: the same cases with `SECURE_MODE=true`.
  When an output check changed an answer, the entry also records which check fired and
  the model's own answer before the check.
- `metrics.json` - `rag-lab eval`: every attack case and eight benign questions, run in
  both modes in one go and scored. It holds per-case before/after verdicts, totals
  (attack block rate, benign accuracy, benign block rate), and the formulas behind them.
  The benign questions measure the cost of the fixes: a fix that blocks or breaks an
  ordinary question is a false positive.

- `llm01-layers.json` - `scripts/llm01_layers.py`: the LLM01 defense layers tested on
  their own. Retrieval runs with `SECURE_MODE` off so the quarantined newsletter still
  reaches the model, and each question is sent with the original prompt, the fenced
  prompt, and the fenced prompt plus the output check. It records how many answers
  contained the injected sentence at each layer, with every answer. It uses its own
  throwaway store and canary file, so the canary value in it differs from the one in
  `findings.json`.

## How to produce them

Run against a real model (Ollama) so the answers are genuine, not the offline fake:

```bash
rag-lab reset
rag-lab ingest
rag-lab attack
```

Or in one step: `rag-lab attack --reingest`. Run a single case with
`rag-lab attack --case LLM02-canary-exfiltration`.

For the after, set `SECURE_MODE=true` and run `rag-lab attack --reingest` again. The
output is named `retest.*` automatically, so it never overwrites the before; `--name`
overrides the file name. `rag-lab eval` runs both modes itself and ignores the
`SECURE_MODE` setting.

The committed `findings.*` come from a real local run. The canary values in them use
the obviously fake `RAL-CANARY-...` format and are generated per machine, so they are
safe to commit; they are not real credentials. The offline tests do not touch this
folder - they test the detectors and the writer directly.
