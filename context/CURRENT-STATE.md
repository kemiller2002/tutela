# Current State

Tutela 0.1.0 executable foundation is established.

Implemented:
- normative security requirements and agent-security rules;
- security lifecycle, self-security profile and integration contracts;
- machine schemas for threats, invariants, evidence, assessments and exceptions;
- deterministic dependency-free posture engine; the F# gate (`src/Tutela.Core`, CLI `tutela`) is the CI authority, and the Python gate is an expiring conformance oracle (docs/decisions/0001-gate-authority.md);
- exception approvals bound to the role registry: human security-owner, distinct from the requester, current;
- versioned result contract `tutela.verification/1` and the canonical sensitive-data catalog `security/SENSITIVE-DATA-RULES.json` (docs/SECURITY-OWNERSHIP.md);
- self secret scan, and a requirement-traceability ratchet (`tutela trace`), in CI;
- semantic gate unit tests covering PASS, BLOCKED, INDETERMINATE, CONDITIONAL, stale/unknown state, contradictions, duplicate IDs and exception expiry;
- CI build of every project in `Tutela.sln` (CI fails if a project is missing from the solution), F# tests, F#/Python parity, and declared-vs-derived posture via the F# CLI;
- results UI specification;
- owning-repository integration requirements added to Forma, Folio, Aegis, Praxis and Conditor.

Open implementation obligations:
- implement Forma Tutela web components and examples;
- implement Folio Security Evidence Record renderer;
- implement Aegis evidence adapter;
- implement Praxis security telemetry adapter;
- implement Conditor Tutela installer/doctor support;
- add richer semantic cross-reference validation and independent-verifier attestations;
- run adversarial experiments against real Echelon applications.

No claim that Tutela or a consuming system is generally secure is implied by this status.
