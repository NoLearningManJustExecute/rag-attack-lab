# Contributing

Thanks for your interest. This is a teaching project, so the bar is clear code, working setup steps, and documented decisions over clever shortcuts.

Before anything else, read [SECURITY.md](SECURITY.md). This application is vulnerable on purpose. Its planted weaknesses are intentional and documented; please don't report them as bugs.

## Development setup

You need Python 3.12 or newer. The model is optional for most work, because the tests and the CI checks run fully offline.

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux:        source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .
```

To run the lab against a real model, install [Ollama](https://ollama.com), pull `llama3.1:8b` and `nomic-embed-text`, then `rag-lab ingest` and `rag-lab ask "..."`. See the [README](README.md) for details.

## Checks to run before you push

CI runs all of these on every push to `main` and every pull request. Run them locally first:

```bash
python -m pytest                 # offline tests
ruff check src tests ci          # lint
ruff format --check src tests ci # formatting
pip-audit -r requirements.txt --ignore-vuln PYSEC-2026-311 --ignore-vuln PYSEC-2026-3813 --ignore-vuln PYSEC-2026-3814 --ignore-vuln PYSEC-2026-3815
```

The promptfoo red-team checks also run in CI. To run them locally you need Node 22 or newer:

```bash
cd ci/promptfoo
npm ci
PROMPTFOO_PYTHON=python npm run eval
```

## How the code is organized

- `src/rag_attack_lab/`: the pipeline, one responsibility per module (config, providers, embeddings, vectorstore, ingest, retriever, rag, cli).
- `data/`: fictional seed documents. Never add real or sensitive data.
- `tests/`: offline tests using the fake chat provider and the deterministic hashing embeddings.
- `ci/promptfoo/`: the offline red-team harness.
- `docs/`: threat model, report, and decision records.

## Branches, commits, and pull requests

- Work on a branch, not directly on `main`.
- Keep each commit focused. Write a clear subject line and a body that explains why.
- Link issues in the commit body: `Closes #12` when the commit finishes the work, `Refs #12` when it only contributes.
- Open a pull request and use the template's checklist.

## Rules for every change

- Never commit real data, real secrets, or secrets in a realistic provider-key format. Use obviously fake markers like `RAL-CANARY-...`. Realistic formats trip GitHub push protection.
- Never start a Chroma server (`chroma run`). The lab uses `chromadb.PersistentClient` in-process only. See the README's "Known dependency advisories".
- Read everything from environment variables with defaults in `config.py` and `.env.example`. Don't hardcode models, paths, or keys.
- Any planted weakness must be documented in `VULNERABILITIES.md` (added with the first planted weakness in v1.0) and mapped to the OWASP Top 10 for LLM Applications (2026) and MITRE ATLAS.
- Keep dependencies lean and pinned.
