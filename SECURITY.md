# Security Policy

## This project is vulnerable on purpose

RAG Attack Lab is a deliberately vulnerable application for AI security education. Its planted weaknesses are documented and intentional. They are not bugs, and reports about them will be closed.

- Run it locally only. Never expose it to a network or the internet.
- Use only the fictional data that ships with it. Never load real documents, credentials, or personal data.
- Never deploy it, or code copied from it, to production.

## What counts as a real security issue

Please report anything that could harm someone who runs the lab as documented, for example:

- A dependency vulnerability that is reachable in the way the lab uses that dependency
- Anything that makes the lab reach the network when the README says it is local-only
- A real secret or real personal data committed to the repository
- A problem in the CI workflows (for example, excessive permissions or an untrusted-input injection)

Known, reviewed dependency advisories are listed in the README under "Known dependency advisories", with the per-advisory triage below under "Supply-chain dependencies".

## Supply-chain dependencies

`chromadb` is pinned at 1.5.9 in `requirements.txt` and `requirements-lock.txt`. That is the latest release, and the four advisories below have no upstream fix, so bumping is not an option today. All four sit in the Chroma server, which this lab never starts.

| Advisory | Title | Affected component | Reachable in this lab | Disposition |
| --- | --- | --- | --- | --- |
| GHSA-f4j7-r4q5-qw2c (CVE-2026-45829) | ChromaDB Python project has a pre-authentication code injection vulnerability | Server endpoint `POST /api/v2/tenants/{tenant}/databases/{db}/collections`, with a model repository and `trust_remote_code` | No | Vulnerable path not used |
| GHSA-36p7-vc44-83pf (CVE-2026-45833) | ChromaDB has a code injection vulnerability | Server endpoint `/api/v2/.../collections/{collection_id}`, with a model repository and `trust_remote_code`, for a user with the `UPDATE_COLLECTION` permission | No | Vulnerable path not used |
| GHSA-2wm9-hf6c-p5cr (CVE-2026-45830) | ChromaDB allows any authenticated users to arbitrarily read, write, update, or delete data in any tenant's collection | Server authorization between authenticated users and tenants | No | Vulnerable path not used |
| GHSA-xph7-9rjv-w5fr (CVE-2026-45831) | ChromaDB's SimpleRBACAuthorizationProvider doesn't check which tenant, database, or collection a permission applies to | `SimpleRBACAuthorizationProvider` in the server's authorization layer | No | Vulnerable path not used |

**How I checked.** I read the advisories, then the code, then ran it on 2026-11-03 with chromadb 1.5.9 installed from the lockfile:

- `src/rag_attack_lab/vectorstore.py` is the one place the lab opens Chroma. Its code passes only a collection name, an embedding function, `persist_directory` and a telemetry setting. Given `persist_directory`, langchain-chroma 1.1.0 creates `chromadb.PersistentClient`, which runs in-process in the default setup. `ingest`, `retrieve`, `ci/promptfoo/provider.py` and `scripts/llm01_layers.py` all go through it.
- Nothing in `src/`, `scripts/`, `ci/promptfoo/` or `docs/demo/demo.ps1` starts a Chroma server.
- I ran `ingest` and `retrieve` through that path with the fake providers. The process owned no TCP sockets, and neither `chromadb.server` nor `chromadb.auth.simple_rbac_authz` was imported. The collection had no embedding function configured.
- `fastapi`, `sentence_transformers` and `transformers` are not installed by the lockfile, and the lab sets no collection configuration. So the lab itself never asks for a model repository, and the code that would load one is missing.

**Why this is tolerable here.** The lab runs locally on fictional data and opens no port, so the attacker these advisories need, one who can send requests to a Chroma server, does not exist in the documented setup.

**Limits.** This is a check of how the lab uses chromadb, not a review of chromadb.

- **Running a server.** The package still installs the `chroma` command, which starts a Chroma server. I did not test whether that server has these flaws. The project rule forbids running it either way.
- **Environment settings.** chromadb's settings also read environment variables and `.env`. Setting `CHROMA_API_IMPL=chromadb.api.fastapi.FastAPI` moves the lab off the in-process client with no code change: I tested it, and the lab then asks for a server host instead of opening the store. It would still need a separate server, and neither setting is in `.env.example`.
- **A store you did not create.** From reading chromadb's code, an upsert also reads a schema stored with the collection, and that schema can name an embedding function. So a tampered store at `CHROMA_DIR` might reach model-loading code in-process, with no server. I did not test that, and the missing `sentence_transformers` package is what stops it. It is not one of these advisories' endpoints, so the table stands, but only use a store the lab built, and do not add that package.
- **When to re-check.** These dispositions stop being true if the lab ever starts a server, connects with `host` or an HTTP client, or passes a collection configuration. Re-check them when a chromadb release ships a fix.

## How to report

Use GitHub's private vulnerability reporting on this repository (Security tab, then "Report a vulnerability"). Please don't open a public issue for a real security problem.

If that button is not available, open an issue asking for a private contact, with no details of the problem.

Include what you found, how to reproduce it, and the commit you tested. I will acknowledge reports within 7 days.

## Supported versions

Only the latest commit on `main` is supported.
