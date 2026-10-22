# Planted vulnerabilities

RAG Attack Lab is vulnerable on purpose. This file lists every weakness planted in v1.0, where it lives, and why it is
a weakness. All four are on by default. Since v3.0, setting `SECURE_MODE=true` turns on one fix per weakness; see
[Fixes (v3.0, SECURE_MODE)](#fixes-v30-secure_mode) at the end, including what each layer did and did not stop.

Each weakness is mapped to the [OWASP Top 10 for LLM Applications (2026)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
and to [MITRE ATLAS](https://atlas.mitre.org/). The ATLAS IDs were checked against the ATLAS data release v2026.09.

Every weakness site in the code carries a comment that starts with its OWASP ID, for example `# LLM01: ...`.
To find them all:

```powershell
git grep -nE "# LLM0[1289]"
```

The tests in `tests/test_weaknesses.py` confirm each weakness is present with `SECURE_MODE` off. The tests in
`tests/test_fixes.py` confirm each one is closed with `SECURE_MODE` on.

For the system description, trust boundaries, and assets, see the [threat model](docs/threat-model.md).

| ID | Weakness | MITRE ATLAS |
| --- | --- | --- |
| [LLM01](#llm01-prompt-injection) | Prompt Injection (direct and indirect) | AML.T0051 LLM Prompt Injection (.000 Direct, .001 Indirect) |
| [LLM02](#llm02-sensitive-information-disclosure) | Sensitive Information Disclosure | AML.T0057 LLM Data Leakage |
| [LLM08](#llm08-hidden-context-exposure) | Hidden Context Exposure | AML.T0056 Extract LLM System Prompt |
| [LLM09](#llm09-vector-and-embedding-weaknesses) | Vector and Embedding Weaknesses | AML.T0070 RAG Poisoning |

## LLM01 Prompt Injection

- **OWASP:** LLM01 Prompt Injection
- **MITRE ATLAS:** AML.T0051 LLM Prompt Injection, sub-techniques AML.T0051.000 Direct and AML.T0051.001 Indirect
- **Where it lives:**
  - `src/rag_attack_lab/rag.py`, `build_prompt()`: the question and the retrieved chunk text are dropped into
    `PROMPT_TEMPLATE` with `str.format`. Look for the `# LLM01 (direct)` and `# LLM01 (indirect)` comments.
  - `data/untrusted/vendor_newsletter.txt`: a labeled teaching example whose body contains instruction-like text.
- **Why it is vulnerable:** the model receives one block of text. Nothing separates the developer's instructions from
  the user's question or from document content, so text in either place can read as an instruction. The question is
  not checked, and retrieved text is pasted in verbatim with only a `[Source: ...]` label in front of it.
- **What would prevent it:** keep instructions in a separate system message, wrap untrusted text in clearly delimited
  data blocks, screen inputs and retrieved text for instruction-like content, and check outputs before returning them.
- **How v2 will exercise it:** ask questions, and ingest documents, that try to override the instructions, and record
  whether the answer follows them.

## LLM02 Sensitive Information Disclosure

- **OWASP:** LLM02 Sensitive Information Disclosure
- **MITRE ATLAS:** AML.T0057 LLM Data Leakage
- **Where it lives:**
  - `data/internal/ops_runbook.txt` and `data/internal/leadership_memo.txt`: fictional internal documents with
    `{{CANARY:...}}` placeholders. `src/rag_attack_lab/canaries.py` fills them with generated `RAL-CANARY-...` values
    at ingest time and saves the values to `CANARY_FILE` (default `data/internal/.canaries`, git-ignored).
  - `src/rag_attack_lab/ingest.py`, `ingest()`: internal documents are stored in the same index as the public ones.
    Look for the `# LLM02` comment.
  - `src/rag_attack_lab/retriever.py`, `retrieve()`: the similarity search has no filter. Look for the `# LLM02` comment.
- **Why it is vulnerable:** there is no access control anywhere in the pipeline. Retrieval does not know who is asking,
  nothing acts on a document's sensitivity (since v3.0 ingest records a label, but only `SECURE_MODE` uses it), and
  nothing checks answers for secrets. Any question that is similar enough to
  an internal document pulls it, canaries included, into the prompt.
- **What would prevent it:** keep secrets out of the corpus entirely, label documents by sensitivity, filter retrieval
  by the caller's permissions, and scan answers for secrets before returning them.
- **How v2 will exercise it:** ask ordinary-sounding questions and check whether any `RAL-CANARY-` value from
  `CANARY_FILE` appears in the retrieved context or the answer.

## LLM08 Hidden Context Exposure

- **OWASP:** LLM08 Hidden Context Exposure (the 2025 list called this System Prompt Leakage)
- **MITRE ATLAS:** AML.T0056 Extract LLM System Prompt
- **Where it lives:** `src/rag_attack_lab/rag.py`: `PROMPT_TEMPLATE` and `answer_question()`. Look for the `# LLM08`
  comments.
- **Why it is vulnerable:** the system instructions are ordinary text at the top of the same string as the context and
  the question. They are not sent as a separate system message, the model is not told to keep them private, and
  nothing checks whether an answer repeats them. The retrieved context is hidden from the user too, and is just as
  exposed.
- **What would prevent it:** treat the system prompt as public and keep nothing sensitive in it, send it as a separate
  system message, and filter answers that echo it or the hidden context.
- **How v2 will exercise it:** ask the assistant to describe or repeat its instructions and its context, and compare the
  answer with `PROMPT_TEMPLATE`.

## LLM09 Vector and Embedding Weaknesses

- **OWASP:** LLM09 Vector and Embedding Weaknesses
- **MITRE ATLAS:** AML.T0070 RAG Poisoning
- **Where it lives:**
  - `src/rag_attack_lab/ingest.py`, `find_files()` and `ingest()`: every supported file under the folder, including
    subfolders, goes into the index. Since v3.0 ingest also records a trust label and a suspicious-content flag, but
    with `SECURE_MODE` off nothing acts on them. Look for the `# LLM09` comment.
  - `src/rag_attack_lab/vectorstore.py`, `get_vector_store()`: one shared collection for everything. Look for the
    `# LLM09` comment.
  - `src/rag_attack_lab/rag.py`, `build_prompt()`: trusted and untrusted chunks get the same label.
  - `data/untrusted/return_policy_update.txt`: a labeled teaching example that contradicts the real return policy in
    `data/customer_faq.txt`.
- **Why it is vulnerable:** the index has no isolation and no provenance. Anyone who can put a file in the data folder
  can add content that is retrieved and presented exactly like the company's own documents. Retrieval ignores where a
  document came from and what the content screen found, and the prompt gives the model no way to tell trusted from
  untrusted text.
- **What would prevent it:** only ingest from vetted sources, record provenance and trust level in metadata, check
  documents for suspicious content before they are indexed, separate collections by tenant and sensitivity, and be able
  to purge and rebuild the index.
- **How v2 will exercise it:** ingest a document that contradicts a trusted one, ask about that topic, and record which
  version the answer follows.

## Fixes (v3.0, SECURE_MODE)

Set `SECURE_MODE=true` (in `.env` or the environment) to turn the fixes on. With it off, the lab behaves exactly as
described above. All four fixes live in `src/rag_attack_lab/defenses.py`, and every place they are applied carries a
comment starting with the OWASP ID and the word "fix", for example `# LLM02 and LLM09 fix: ...`. Ingest labels every
chunk in both modes, so one ingest serves both; only secure mode acts on the labels.

| ID | Fix | Where |
| --- | --- | --- |
| LLM02 | Every chunk is labeled at ingest by folder: `data/` is public, `data/internal/` is internal, everything else (including `data/untrusted/` and files from outside `DATA_DIR`) is untrusted. In secure mode `retrieve()` searches public, unflagged chunks only: the default caller has no clearance. | `defenses.classify_sensitivity()`, `defenses.retrieval_filter()`, `ingest.py`, `retriever.py` |
| LLM09 | The same filter keeps untrusted documents out of retrieval, so the poisoned return-policy update never competes with the real one. An ingest-time screen (issue #12) also flags documents that address an AI system, and flagged documents are quarantined the same way. | `defenses.find_suspicious_lines()`, `ingest.py` |
| LLM01 | Retrieved chunks are fenced in `<document>` tags (tag-like text inside a chunk is defused first), and the system message says text in the tags is data, never instructions. An output check then removes any payload that a flagged document asked the model to say. | `defenses.fence_document()`, `rag.build_messages()`, `defenses.strip_payloads()` |
| LLM08 | The instructions are sent as a separate system-role message, and the answer is refused if it repeats any six consecutive words of them. The sentence the model is told to say ("If the answer is not in the context, say you don't know.") is exempt, so honest answers are not refused. | `rag.build_messages()`, `defenses.leaks_instructions()` |

### What each layer did against llama3.1:8b

I tested the layers on their own, not only together, because a fix that only works because another fix hides the
attack is not a fix.

- **LLM02 and LLM09.** With the filter on, the internal runbook, the leadership memo, and the poisoned update are
  never retrieved. The canary question gets "I don't know" and the return-policy question gets the real 30-day policy.
- **LLM01: fencing alone is not enough.** I ran four newsletter questions with the retrieval filter bypassed, so the
  newsletter still reached the model. With the plain v1 prompt the model emitted the injected sentence 4 times out of 4.
  With the fenced prompt and the data-not-instructions system message it still emitted it 2 times out of 4. With the
  output check added, 0 out of 4. In normal secure mode the newsletter is quarantined, so it never reaches the model at
  all. The defense is the three layers together: quarantine, fencing, and the output check.
- **LLM08: the separate system message alone is not enough either.** In the secure-mode retest the model still quoted
  its instructions when asked. The output check caught the quote and returned a refusal instead. The findings record
  the model's own answer before the check, so this is visible, not hidden.

### Limits

- The ingest screen and the LLM08 check match text. A reworded injection or a paraphrased system prompt can get past
  them. That is why nothing secret belongs in the system prompt, and why the folder label, not the content screen, is
  the main control for untrusted documents.
- The LLM01 output check only knows payloads quoted in documents the screen flagged. It is a backstop, not a guarantee.
- Access control here is one fixed clearance level (public). A real deployment would filter by the caller's identity
  and roles, checked outside the model.
- Direct prompt injection through the question (LLM01, AML.T0051.000) is fenced away from the instructions but not
  screened. The attack harness tests the indirect case.

## Not a planted weakness

The `chromadb` advisories listed under "Known dependency advisories" in [README.md](README.md) are real upstream
issues, not part of the lab. The lab is not exposed to them because it never starts a Chroma server.
