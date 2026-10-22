# Pentest Report Outline

## 1. Executive Summary

Three to five sentences for a non-technical reader explaining what was tested, the most serious finding, overall risk posture before remediation, and security posture after fixes.

## 2. Scope and Rules of Engagement

Define what is in scope (RAG Attack Lab, local environment, fictional data), what is out of scope, testing constraints, and the testing window.

## 3. Environment

Document hardware, operating system, Python version, dependency versions, application version, Git commit hash, LLM name and version, generation settings (temperature, top-p, max tokens), embedding model, vector store version, chunk size, chunk overlap, retrieval parameters, and dataset versions.

## 4. Methodology

Describe testing activities mapped to OWASP Top 10 for LLM Applications (2026) and MITRE ATLAS. Include manual testing, automated testing, attack categories, and all tools used.

## 5. Severity Rating Method

Explain the severity scale (Critical, High, Medium, Low), how ratings are assigned, and the factors considered such as impact, exploitability, likelihood, detection difficulty, and data exposure.

## 6. Findings

One section per finding using the following template:

| Field | Content |
|---|---|
| ID | Unique finding ID |
| Title | Short description |
| Discovery Date | Date identified |
| Severity | Critical / High / Medium / Low |
| Risk Score | Optional numeric score |
| OWASP ID | OWASP LLM Top 10 (2026) category |
| ATLAS ID | MITRE ATLAS technique |
| Affected Components | Impacted system components |
| Description | Technical explanation of the weakness |
| Attack Scenario | How the issue can be exploited |
| Evidence | Logs, screenshots, transcripts, or test output |
| Impact | What an attacker gains |
| Root Cause | Why the weakness exists |
| Remediation | Fix applied |
| Retest Result | Whether the fix holds, with evidence |
| Status | Open, Mitigated, or Closed |

## 7. Metrics Before and After Fixes

Present attack-block rate, false-positive rate, benign success rate, and evaluation accuracy before and after remediation. Include formulas and percentage improvements.

## 8. Retest Summary

Summarize which findings were closed, which remain open, residual risks, and reasons unresolved findings remain.

## 9. Lessons Learned

Describe what worked well, what did not work, key security improvements, and recommendations for future testing.

## 10. Appendix

Include raw evaluation output, tool configurations, environment details, reproduction steps, evidence archives, remediation commit references, and framework mapping tables linking findings to OWASP and MITRE ATLAS.
