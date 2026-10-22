# RAG Attack Lab

> **Vulnerable by design.** This is a deliberately insecure RAG application for AI security education, in the same spirit as other intentionally vulnerable training applications.
> **Local only.** Run it on your own machine. Never deploy it or expose it to a network.
> **Fake data only.** Every document in this repo is invented. Never load real or sensitive data into it.

**Status: v0.1 baseline.** This version is a clean, working RAG pipeline with no planted vulnerabilities. Vulnerabilities and attack exercises land in v1.0.

See [docs/OVERVIEW.md](docs/OVERVIEW.md) for the full project overview, [ROADMAP.md](ROADMAP.md) for project phases, [CONTRIBUTING.md](CONTRIBUTING.md) to get set up, and [SECURITY.md](SECURITY.md) for the security policy.

[![CI](https://github.com/NoLearningManJustExecute/rag-attack-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/NoLearningManJustExecute/rag-attack-lab/actions/workflows/ci.yml)

## What it does

1. **Ingest:** loads `.txt` and `.pdf` files, splits them into chunks, embeds them with `nomic-embed-text` via Ollama, and stores them in a local Chroma database.
2. **Ask:** embeds your question, retrieves the top-k most similar chunks (with their source files), puts them into a prompt, and asks a local model (`llama3.1:8b` via Ollama by default) to answer.

The seed documents in `data/` describe a fictional company, Northwind Gadgets: an employee handbook, a product overview, and a customer FAQ.

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
| `DATA_DIR` | `data` | Default folder for `ingest` |
| `CHUNK_SIZE` / `CHUNK_OVERLAP` | `800` / `100` | Chunking, in characters |
| `TOP_K` | `4` | How many chunks to retrieve |
| `LLM_TEMPERATURE` | `0` | Sampling temperature |

The Anthropic provider is optional. It only needs `langchain-anthropic` (included in `requirements.txt`) and an API key. Note that using it sends your prompts, including retrieved document text, to an external API, so the lab is no longer fully local.

## Usage

```powershell
# Ingest the seed documents (or pass a file or folder)
rag-lab ingest
rag-lab ingest path\to\folder

# Ask a question
rag-lab ask "How many vacation days do employees get?"

# Also print the full prompt sent to the model
rag-lab ask "What is the return policy?" --show-prompt

# Delete everything in the vector store
rag-lab reset
```

`python -m rag_attack_lab.cli <command>` works too. Running `ingest` twice stores the documents twice, so run `reset` first if you want a clean store.

## Tests

The tests run fully offline. They use a fake chat model and a deterministic bag-of-words embedding, so Ollama does not need to be running.

```powershell
python -m pytest
```

Lint and dependency checks use the tools pinned in `requirements-dev.txt`:

```powershell
pip install -r requirements-dev.txt
ruff check src tests
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
  ingest.py       load TXT/PDF, chunk, store
  retriever.py    top-k search with source metadata
  rag.py          retrieve, build prompt, generate
  cli.py          ingest / ask / reset commands
data/             fictional seed documents
tests/            offline tests
```

## License

MIT. See [LICENSE](LICENSE).
