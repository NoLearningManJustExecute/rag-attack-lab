# RAG Attack Lab

> **Vulnerable by design.** This is a deliberately insecure RAG application for AI security education, in the same spirit as other intentionally vulnerable training applications.
> **Local only.** Run it on your own machine. Never deploy it or expose it to a network.
> **Fake data only.** Every document in this repo is invented. Never load real or sensitive data into it.

**Status: attacked, fixed, retested, and written up.** Four deliberately planted, documented weaknesses; an attack harness (`rag-lab attack`) that exploits them; one fix per weakness behind `SECURE_MODE=true`; a measured retest (4/4 attacks before, 0/4 after, no benign answers lost); a [pentest report](docs/report/pentest-report.md); and a [two-minute demo script](docs/demo/README.md). Results are [below](#results-before-and-after-the-fixes).

See [docs/OVERVIEW.md](docs/OVERVIEW.md) for the full project overview, [ROADMAP.md](ROADMAP.md) for project phases, [CONTRIBUTING.md](CONTRIBUTING.md) to get set up, and [SECURITY.md](SECURITY.md) for the security policy.

[![CI](https://github.com/NoLearningManJustExecute/rag-attack-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/NoLearningManJustExecute/rag-attack-lab/actions/workflows/ci.yml)

## Demo

![The same four attacks against a local llama3.1:8b: all four succeed with SECURE_MODE off (top), all four fail with it on (bottom).](docs/demo/images/hero_before-after.png)

Four attacks against a local `llama3.1:8b`: **4 of 4 succeed** against the vulnerable lab, **0 of 4** after the fixes, with everyday questions still answered correctly. Full step-by-step walkthrough and screenshots: [docs/demo](docs/demo/).

## What it does

1. **Ingest:** loads `.txt` and `.pdf` files, splits them into chunks, embeds them with `nomic-embed-text` via Ollama, and stores them in a local Chroma database.
2. **Ask:** embeds your question, retrieves the top-k most similar chunks (with their source files), puts them into a prompt, and asks a local model (`llama3.1:8b` via Ollama by default) to answer.

The seed documents in `data/` describe a fictional company, Northwind Gadgets: an employee handbook, a product overview, and a customer FAQ. `data/internal/` holds fictional internal documents with canary secrets, and `data/untrusted/` holds two labeled teaching examples. All of them go into the same index.

## Architecture

![Architecture of the RAG pipeline with the four planted weaknesses pinned where they occur](docs/images/architecture.png)

`SECURE_MODE=true` closes LLM02/LLM09 structurally (ingest labels + retrieval filter) and mitigates LLM01/LLM08 (prompt fencing, separate system role, output checks).

<details>
<summary>Diagram source (Mermaid)</summary>

```mermaid
flowchart TD
    subgraph ingest[Ingest]
        D["data/ files<br/>public · internal · untrusted"] --> L["load"]
        L --> CAN["fill canary secrets"]
        CAN --> CH["chunk"]
        CH --> VS[("Chroma<br/>one collection; labels stored, not enforced")]
    end

    Q["User question"] --> RET["retrieve top-k"]
    VS --> RET
    RET --> BP["build prompt<br/>system instructions + context + question"]
    BP --> LLM["LLM (llama3.1:8b)"]
    LLM --> ANS["Answer to user"]

    Q -. "untrusted input (boundary 1)" .-> BP
    D -. "untrusted content (boundary 2)" .-> BP

    RET -.->|"no access control"| W02["LLM02 Sensitive Info Disclosure / AML.T0057"]
    VS -.->|"untrusted ranked = trusted"| W09["LLM09 Vector &amp; Embedding Weaknesses / AML.T0070"]
    BP -.->|"data concatenated as instructions"| W01["LLM01 Prompt Injection / AML.T0051.001"]
    BP -.->|"system prompt in plain text"| W08["LLM08 Hidden Context Exposure / AML.T0056"]

    classDef weakness fill:#fff0f0,stroke:#c0392b,color:#c0392b;
    class W01,W02,W08,W09 weakness;
```

</details>

## Deliberately planted vulnerabilities

Four weaknesses are planted on purpose and are on by default (`SECURE_MODE=false`). Each is mapped to the OWASP Top 10 for LLM Applications (2026) and MITRE ATLAS, and tagged in the code with a `# LLM0x:` comment.

- **LLM01 Prompt Injection** (ATLAS AML.T0051, .000 Direct and .001 Indirect): the question and retrieved document text are pasted into the prompt with no separation of instructions from data.
- **LLM02 Sensitive Information Disclosure** (ATLAS AML.T0057 LLM Data Leakage): internal documents with canary secrets share the index with public ones, and retrieval has no access control.
- **LLM08 Hidden Context Exposure** (ATLAS AML.T0056 Extract LLM System Prompt): the system instructions are plain text in the same prompt string, with nothing to stop them being repeated.
- **LLM09 Vector and Embedding Weaknesses** (ATLAS AML.T0070 RAG Poisoning): one shared index with no isolation or provenance, and untrusted documents are ingested and presented like trusted ones.

Details, code locations, and what would prevent each one are in [VULNERABILITIES.md](VULNERABILITIES.md). The trust boundaries and assets are in the [threat model](docs/threat-model.md).

Canary values are generated on your machine at ingest time in an obviously fake `RAL-CANARY-...` format and saved to `CANARY_FILE`, which is git-ignored. The committed documents only hold `{{CANARY:...}}` placeholders.

## Results: before and after the fixes

One attack harness, run against `llama3.1:8b` with the fixes off and on. Before is the default, vulnerable lab; after is the same lab with `SECURE_MODE=true`.

| Case | OWASP (2026) | MITRE ATLAS | Severity | Before | After |
| --- | --- | --- | --- | --- | --- |
| Internal runbook secrets exfiltrated | LLM02 Sensitive Information Disclosure | AML.T0057 | Critical | VULNERABLE | not triggered |
| System instructions disclosed | LLM08 Hidden Context Exposure | AML.T0056 | Medium | VULNERABLE | not triggered |
| Instruction in a retrieved document obeyed | LLM01 Prompt Injection | AML.T0051.001 | High | VULNERABLE | not triggered |
| Poisoned document overrides the return policy | LLM09 Vector and Embedding Weaknesses | AML.T0070 | High | VULNERABLE | not triggered |

| Metric | Before | After |
| --- | --- | --- |
| Attacks triggered | 4/4 | 0/4 |
| Benign questions answered correctly | 8/8 | 8/8 |
| Benign questions blocked by an output check (false positives) | 0/8 | 0/8 |

The fixes are not equally strong. The LLM02 and LLM09 fixes are structural: retrieval filters on labels set at ingest, so internal and untrusted documents never reach the model. The LLM01 and LLM08 fixes are mitigations: on their own, the prompt changes still let the model leak 2 of 4 times (LLM01) or quote its instructions (LLM08), and text-matching output checks catch what is left. A reworded or translated attack could get past those checks. In the committed retest, the LLM01 case passes because the newsletter is quarantined and never retrieved; the fencing and the output check were measured separately, with the quarantine bypassed. [VULNERABILITIES.md](VULNERABILITIES.md#fixes-v30-secure_mode) has the per-layer results and the limits.

Evidence: [findings/findings.md](findings/findings.md) (before), [findings/retest.md](findings/retest.md) (after), and [findings/metrics.json](findings/metrics.json) (both runs, scored). Each one holds the model's own answers. The before has no output checks, so its benign block rate is 0 by construction.

### How to reproduce

Needs Ollama with `llama3.1:8b` and `nomic-embed-text` (see Setup below). Every step stays on your machine.

```powershell
# Before: the vulnerable default. Writes findings\findings.json and findings\findings.md.
rag-lab attack --reingest

# After: the same attacks with the fixes on. Writes findings\retest.json and findings\retest.md.
$env:SECURE_MODE = "true"
rag-lab attack --reingest
Remove-Item Env:SECURE_MODE

# Both runs plus the benign questions, scored. Writes findings\metrics.json.
rag-lab eval
```

Model answers can vary between machines and model builds, even at temperature 0. The verdicts above are from the committed run.

To test the LLM01 layers on their own (quarantine bypassed, so the newsletter reaches the model), run `python scripts\llm01_layers.py`. It writes `findings\llm01-layers.json`; the committed run found the injected sentence in 4 of 4 answers with the original prompt, 2 of 4 with fencing alone, and 0 of 4 with fencing plus the output check.

### Two-minute demo

`.\docs\demo\demo.ps1` runs the whole story from a clean store: ingest, attack (4/4), turn on `SECURE_MODE`, attack again (0/4). It pauses between steps for narration, writes to the git-ignored `demo_output\`, and never touches `findings\`. Recording steps and a suggested narration are in [docs/demo/README.md](docs/demo/README.md).

### Pentest report

The full write-up is [docs/report/pentest-report.md](docs/report/pentest-report.md), with a PDF copy at [docs/report/pentest-report.pdf](docs/report/pentest-report.pdf): executive summary, scope, methodology, the four findings with the model's own answers as evidence, retest, metrics, residual risk, and the framework mapping. To rebuild the PDF after editing the markdown, run `python scripts\render_report.py` (it prints with a local Edge or Chrome in headless mode; nothing is fetched from the network).

## Requirements

- Windows with PowerShell (the steps below use PowerShell)
- Python 3.12
- [Ollama](https://ollama.com) running on `localhost:11434`

## Setup (Windows, PowerShell)

```powershell
# 1. Pull the models
ollama pull llama3.1:8b
ollama pull nomic-embed-text

# 2. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# 3. Install dependencies and the package itself
pip install -r requirements.txt
pip install -e .

# 4. Create your local config
Copy-Item .env.example .env
```

If PowerShell refuses to run `Activate.ps1`, allow local scripts for your user once:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

## Configuration

All settings come from environment variables. Defaults live in `src/rag_attack_lab/config.py`, and every variable is listed in `.env.example`. Put your overrides in `.env` (it is git-ignored).

| Variable | Default | Meaning |
| --- | --- | --- |
| `LLM_PROVIDER` | `ollama` | `ollama`, `anthropic` (optional), or `fake` (offline, for tests) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Where Ollama is running |
| `OLLAMA_CHAT_MODEL` | `llama3.1:8b` | Chat model for answers |
| `ANTHROPIC_MODEL` | `claude-sonnet-5-5` | Used only when `LLM_PROVIDER=anthropic` |
| `ANTHROPIC_API_KEY` | (empty) | Used only when `LLM_PROVIDER=anthropic` |
| `EMBEDDING_PROVIDER` | `ollama` | `ollama` or `fake` (offline, for tests) |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text` | Embedding model |
| `CHROMA_DIR` | `chroma_db` | Folder for the local vector database |
| `CHROMA_COLLECTION` | `rag_attack_lab` | Chroma collection name |
| `DATA_DIR` | `data` | Default folder for `ingest` (subfolders included) |
| `CANARY_FILE` | `data/internal/.canaries` | Where `ingest` saves the canary values it generates (git-ignored) |
| `CHUNK_SIZE` / `CHUNK_OVERLAP` | `800` / `100` | Chunking, in characters |
| `TOP_K` | `4` | How many chunks to retrieve |
| `LLM_TEMPERATURE` | `0` | Sampling temperature |
| `SECURE_MODE` | `false` | `true` turns on the v3 fixes, one per planted weakness (see [VULNERABILITIES.md](VULNERABILITIES.md#fixes-v30-secure_mode)) |

The Anthropic provider is optional. It only needs `langchain-anthropic` (included in `requirements.txt`) and an API key. Note that using it sends your prompts, including retrieved document text, to an external API, so the lab is no longer fully local.

## Usage

```powershell
# Check the setup: providers, Ollama and its models, and the vector store
rag-lab doctor

# Ingest the seed documents (or pass a file or folder)
rag-lab ingest
rag-lab ingest path\to\folder

# Ask a question
rag-lab ask "How many vacation days do employees get?"

# Also print the full prompt sent to the model
rag-lab ask "What is the return policy?" --show-prompt

# Run the four attack cases and write findings (retest.* when SECURE_MODE is on)
rag-lab attack --reingest

# Run everything in both modes and write before/after metrics
rag-lab eval

# Delete everything in the vector store
rag-lab reset
```

`python -m rag_attack_lab.cli <command>` works too. Running `ingest` again on the same files overwrites their chunks instead of adding duplicates. If you edit or remove a file, run `reset` and then `ingest` so its old chunks are dropped.

`doctor` prints the active settings, then PASS, FAIL, or SKIP for each check, and exits with a non-zero code if any check fails. It only contacts Ollama when `LLM_PROVIDER` or `EMBEDDING_PROVIDER` is `ollama`.

## Tests

The tests run fully offline. They use a fake chat model and a deterministic bag-of-words embedding, so Ollama does not need to be running.

```powershell
python -m pytest
```

Lint and dependency checks use the tools pinned in `requirements-dev.txt`:

```powershell
pip install -r requirements-dev.txt
ruff check src tests ci scripts
pip-audit -r requirements.txt --ignore-vuln PYSEC-2026-311 --ignore-vuln PYSEC-2026-3813 --ignore-vuln PYSEC-2026-3814 --ignore-vuln PYSEC-2026-3815
```

CI runs all three on every push to `main` and every pull request, except changes that touch only docs: tests, lint, and the dependency audit. Tests run on Ubuntu every time, and on Windows for pull requests and a weekly scheduled run. The audit ignores only the four chromadb advisories below; any new advisory fails the build. pip-audit reports "5 ignored" because it lists one of the four twice.

## Known dependency advisories

`chromadb` 1.5.9, the latest release, has four open advisories with no patched version yet. They are real upstream issues, not one of this lab's deliberate weaknesses.

| CVE | GHSA | Severity | Issue |
| --- | --- | --- | --- |
| CVE-2026-45829 | GHSA-f4j7-r4q5-qw2c | Critical | Unauthenticated code execution via `trust_remote_code` on the create-collection endpoint |
| CVE-2026-45833 | GHSA-36p7-vc44-83pf | Critical | Authenticated code execution via `trust_remote_code` on the update-collection endpoint |
| CVE-2026-45830 | GHSA-2wm9-hf6c-p5cr | High | Any authenticated user can read or change any tenant's collections |
| CVE-2026-45831 | GHSA-xph7-9rjv-w5fr | High | `SimpleRBACAuthorizationProvider` ignores tenant, database, and collection scope |

**Affected component:** the Chroma HTTP server (its `/api/v2` endpoints and auth providers).

**Why this lab is not exposed:**

- `vectorstore.py` opens Chroma with `persist_directory`, which uses `chromadb.PersistentClient`. It runs in-process and stores data in `CHROMA_DIR`. No server is started and no port is opened.
- The lab never sets `trust_remote_code` and does not use Chroma's built-in embedding functions. Embeddings come from Ollama (or the fake provider) through LangChain.

**Rule:** never run `chroma run` or any Chroma server in this project. The pin stays at 1.5.9 until a patched release ships. Then bump it and remove this section.

## Project layout

```
src/rag_attack_lab/
  config.py       settings from environment variables
  providers.py    chat models: ollama, anthropic (optional), fake
  embeddings.py   embeddings: ollama, fake (offline)
  vectorstore.py  opens the local Chroma store
  canaries.py     generate and fill canary values at ingest time
  ingest.py       load TXT/PDF, chunk, store
  retriever.py    top-k search with source metadata
  rag.py          retrieve, build prompt, generate
  defenses.py     the v3 fixes, active only when SECURE_MODE is on
  attacks/        the attack harness: cases, detectors, runner, metrics
  cli.py          ingest / ask / attack / eval / reset / doctor commands
data/             fictional seed documents
  internal/       fictional internal documents with canary placeholders
  untrusted/      labeled teaching examples (injection, poisoning)
docs/             overview, threat model, pentest report, demo script
tests/            offline tests
scripts/          the LLM01 layer test and the report renderer
findings/         attack evidence: before, retest, metrics, LLM01 layers
VULNERABILITIES.md  the planted weaknesses
```

## License

MIT. See [LICENSE](LICENSE).
