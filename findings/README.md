# Findings

This folder holds the output of the attack harness (`rag-lab attack`).

- `findings.json` - machine-readable results: one object per attack case, with the
  verdict, evidence, the question sent, the model answer, and the retrieved sources.
- `findings.md` - the same results as report-ready markdown: a summary table and one
  section per case with OWASP ID, MITRE ATLAS technique, severity, impact, and
  remediation. This feeds the PDF report (see `docs/report/OUTLINE.md`).

## How to produce them

Run against a real model (Ollama) so the answers are genuine, not the offline fake:

```bash
rag-lab reset
rag-lab ingest
rag-lab attack
```

Or in one step: `rag-lab attack --reingest`. Run a single case with
`rag-lab attack --case LLM02-canary-exfiltration`.

The committed `findings.*` come from a real local run. The canary values in them use
the obviously fake `RAL-CANARY-...` format and are generated per machine, so they are
safe to commit; they are not real credentials. The offline tests do not touch this
folder - they test the detectors and the writer directly.
