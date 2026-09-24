# Current State

Tutela 0.1.0 executable foundation is established.

Implemented:
- normative security requirements and agent-security rules;
- security lifecycle, self-security profile and integration contracts;
- machine schemas for threats, invariants, evidence, assessments and exceptions;
- deterministic dependency-free posture engine;
- semantic gate unit tests covering PASS, BLOCKED, INDETERMINATE, CONDITIONAL, stale/unknown state, contradictions, duplicate IDs and exception expiry;
- CI execution of syntax validation, unit tests and declared-vs-derived example posture;
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
