# promptfoo checks

Offline checks that run the RAG pipeline through a Python provider using the fake chat
model and the deterministic hashing embeddings: no model, no network, no secrets. They
assert that the pipeline retrieves the right document and grounds the prompt in it, and
they fail the build if any assertion fails. The attack cases are not here. They live in
`rag-lab attack` ([src/rag_attack_lab/attacks/](../../src/rag_attack_lab/attacks/)).

GitHub Actions runs this in the `red-team` job (see `.github/workflows/ci.yml`) on Node
22.23.4. To run it locally you need Node 22.22 or newer, which promptfoo 0.125.1 requires,
and the Python package installed from the repository root:

```bash
cd ci/promptfoo
npm ci
PROMPTFOO_PYTHON=python npm run eval
```

Expected output: 3 passed, 0 failed.

- `provider.py` ingests the seed documents once into a temporary store and answers each query.
- `promptfooconfig.yaml` holds the checks.
- `package.json` pins promptfoo with a lockfile, and pins three transitive packages through
  `overrides` to versions that fix advisories. Dependabot tracks the npm ecosystem here.

## Overrides

| Package | Version | Why |
| --- | --- | --- |
| `@azure/identity` | 4.14.1 | Moves `@azure/msal-node` to 7.1.1, past GHSA-xcx6-jx8p-x3h5 |
| `body-parser` | 2.4.0 | Past GHSA-27r3-jxmh-p828 |
| `node-forge` | 1.4.2 | Past the node-forge advisories fixed in 1.4.1 |

Each one stays inside the range its parent asks for, so no override is a major bump of the
package it names. `@azure/identity` 4.14.1 itself asks for `@azure/msal-node@^7.1.0`, so its copy moves
from 6 to 7, the major version promptfoo already used. This harness uses no Azure provider. Remove an
override once a promptfoo release resolves to that version or later by itself.

## Known dependency advisories (npm, dev only)

`npm audit` still reports these. The only fixes are major bumps past what their parents allow,
so they are accepted, not fixed. Dependabot's security job for minimatch fails for the same
reason: promptfoo and its dependencies ask for `minimatch@^10`, and the fix is in 11.

| Package | Version | GHSA | Severity | Issue | Fix needs |
| --- | --- | --- | --- | --- | --- |
| basic-ftp | 5.3.1 | GHSA-c475-qrg2-pj4r | High | Quadratic-time CPU denial of service in the FTP directory-listing parser | 6.x, `get-uri` asks for `^5.3.1` |
| minimatch | 10.2.6 | GHSA-g3hv-75wg-m249 | Moderate | Denial of service through globparts amplification | 11.x, promptfoo asks for `^10.2.4` |
| glob | 13.0.6 | GHSA-3g3m-2fjr-6pw4 | Moderate | AbortSignal cancellation bypass allows filesystem traversal after a timeout | 14.x, promptfoo asks for `^13.0.6` |

`npm audit` also lists the packages that depend on these (`get-uri`, `pac-proxy-agent`,
`proxy-agent`, `@modelcontextprotocol/server-filesystem` and `promptfoo` itself). They have no
advisory of their own here.

**Why this harness is not exposed:**

- All of these are transitive dependencies of `promptfoo`, used only to run the offline CI
  checks. They are not part of the lab and are never shipped.
- The harness runs in an ephemeral CI runner against our own fixtures. It makes no FTP
  connections (basic-ftp), passes no untrusted glob patterns (minimatch), and sets no
  cancellable glob walk over untrusted paths (glob).

**Plan:** when a promptfoo release moves to fixed versions, bump promptfoo and remove this
note. Dependabot will open that pull request.
