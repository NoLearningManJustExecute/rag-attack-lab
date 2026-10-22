# promptfoo red-team harness

Offline checks that run the RAG pipeline through a Python provider using the fake chat
model and the deterministic hashing embeddings: no model, no network, no secrets. They
assert that the pipeline retrieves the right document and grounds the prompt in it, and
they fail the build if any assertion fails. Real attack cases are added here from v2.0.

GitHub Actions runs this in the `red-team` job (see `.github/workflows/ci.yml`). To run
it locally you need Node 22 or newer:

```bash
cd ci/promptfoo
npm ci
PROMPTFOO_PYTHON=python npm run eval
```

- `provider.py` ingests the seed documents once into a temporary store and answers each query.
- `promptfooconfig.yaml` holds the checks.
- `package.json` pins promptfoo with a lockfile; Dependabot tracks the npm ecosystem here.

## Known dependency advisories (npm, dev only)

promptfoo pulls in three transitive packages with open high-severity advisories and **no
fix reachable without a breaking major-version bump** as of the pin below. They are
accepted, not fixed, for the reasons here. These are development/CI tooling only — the lab
itself is Python and ships none of them.

| Package | Version | GHSA | Issue |
| --- | --- | --- | --- |
| basic-ftp | 5.3.1 | GHSA-c475-qrg2-pj4r | Quadratic-time CPU denial of service in the FTP directory-listing parser |
| braces | 3.0.3 | GHSA-vfj7-8cjw-p6xm | Stack-exhaustion denial of service through deeply nested patterns |
| node-forge | 1.4.0 | GHSA-86w9-cpqp-85rv | RSA PKCS#1 v1.5 signature verification accepts extra nested elements |

**Why this harness is not exposed:**

- All three are transitive dependencies of `promptfoo`, used only to run the offline CI
  checks. They are not part of the lab and are never shipped.
- The harness runs in an ephemeral CI runner against our own fixtures. It makes no FTP
  connections (basic-ftp), passes no untrusted glob patterns (braces), and verifies no
  untrusted signatures (node-forge), so the vulnerable code paths are not reached.
- `promptfoo` is already at its latest release, and npm offers no non-downgrade fix.

**Plan:** keep the pin until promptfoo ships a release that updates these transitive
dependencies, then bump promptfoo and remove this note. Dependabot will open that PR.
