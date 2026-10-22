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

Known, reviewed dependency advisories are listed in the README under "Known dependency advisories".

## How to report

Use GitHub's private vulnerability reporting on this repository (Security tab, then "Report a vulnerability"). Please don't open a public issue for a real security problem.

If that button is not available, open an issue asking for a private contact, with no details of the problem.

Include what you found, how to reproduce it, and the commit you tested. I will acknowledge reports within 7 days.

## Supported versions

Only the latest commit on `main` is supported.
