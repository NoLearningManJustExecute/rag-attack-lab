# Two-minute demo

One take, one terminal: ingest the fictional company documents, attack the vulnerable lab (all four attacks
succeed), turn on `SECURE_MODE`, and attack again (none succeed). Everything runs on your machine against a local
model.

`demo.ps1` runs the sequence for you and pauses between steps so you can talk over it. The demo writes to
`demo_output\` (git-ignored), never to `findings\`, so the committed evidence stays as it is.

## Before you record

1. Ollama is running and has both models:
   ```powershell
   ollama list   # llama3.1:8b and nomic-embed-text
   ```
2. The virtual environment is set up (README.md, Setup). From the repo root:
   ```powershell
   .venv\Scripts\Activate.ps1
   ```
3. Warm the model once so the first answer in the recording is not slow:
   ```powershell
   rag-lab ask "How many vacation days do employees get?"
   ```
4. Make the terminal readable: font size 16 or more, a window about 120 columns wide (the result tables need it), and
   clear the screen with `cls`.
5. Do a dry run with `.\docs\demo\demo.ps1 -NoPause` and check that it ends with `0/4 attack(s) triggered.`
   No earlier ingest is needed: the script resets the store and ingests first.

## Recording

Any screen recorder works. Two that are already on Windows or free:

- **Xbox Game Bar** (built into Windows): click the terminal window, press `Win+Alt+R` to start, and press it again to
  stop. The video is saved to `Videos\Captures`.
- **OBS Studio**: add a Window Capture source for the terminal and press Start Recording.

Then run:

```powershell
.\docs\demo\demo.ps1
```

Run it directly; do not pipe or redirect its output. It switches to the repo root by itself. Press Enter at each pause
when you are ready to move on. Without pauses the whole run takes about 75 seconds on the machine in the report; the
two attack runs take most of that. If any step fails, the script stops with a red message instead of showing a
misleading result.

## What happens, step by step

The script runs exactly these commands. You can also type them yourself.

| Step | Command | What to point out |
| --- | --- | --- |
| 1 | `rag-lab reset` then `rag-lab ingest` | A clean store. Ingest lists the documents that are not public (internal and untrusted) and says they are retrievable because `SECURE_MODE` is off. |
| 2 | `rag-lab doctor` | Local model, local embeddings, local vector store, all passing. `secure_mode` is `False`. |
| 3 | `rag-lab attack --out demo_output` | All four attacks marked VULNERABLE, with the evidence column showing the leaked canary, the system-prompt text, the injected sentence, and the 365-day policy. Ends with `4/4 attack(s) triggered.` |
| 4 | `$env:SECURE_MODE = "true"` | One switch. Same code, same documents, same model. |
| 5 | `rag-lab attack --out demo_output` | All four marked not triggered. Ends with `0/4 attack(s) triggered.` |

The script starts with `SECURE_MODE` off whatever your `.env` says, and puts the variable back the way it was when it
finishes.

## Suggested narration (about 2 minutes)

- **0:00** This is a RAG assistant for a made-up company, running entirely on my machine. It is vulnerable on purpose.
- **0:15** I start from an empty store and ingest seven fictional documents: public ones, two internal ones with fake
  secrets, and two untrusted ones planted by an attacker. Everything runs locally.
- **0:30** Four ordinary questions. Every one works: a database password leaks, the assistant repeats its hidden
  instructions, a vendor's planted sentence ends up in the answer, and a fake policy promises 365-day cash refunds.
- **1:00** I turn on one switch, `SECURE_MODE`. Documents are labeled at ingest and retrieval only sees public ones;
  retrieved text is fenced as data; and two output checks catch what the model still gets wrong.
- **1:20** Same four attacks: none succeed. The password and the fake policy are closed by design. The other two are
  mitigated: text-matching checks a reworded attack could get past. The full write-up is in the pentest report.

## Afterwards

- `demo_output\findings.md` and `demo_output\retest.md` (and the matching `.json` files) hold the full answers from
  the recorded run.
- Delete `demo_output\` when you are done, or keep it; git ignores it.
- The committed evidence and the full numbers are in `findings\` and `docs\report\pentest-report.md`.
