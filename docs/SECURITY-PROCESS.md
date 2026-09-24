# Tutela Security Process

1. Scope: release/commit, assets, actors, environment, assumptions.
2. Model: boundaries, flows, capabilities, external effects.
3. Threat: attack/abuse scenarios and forbidden outcomes.
4. Specify: protections as security invariants.
5. Control: map preventive/detective/recovery controls.
6. Verify: gather reproducible and independently corroborated evidence.
7. Reconcile: findings, contradictions, stale evidence, unknown effects.
8. Gate: derive PASS, CONDITIONAL, BLOCKED or INDETERMINATE.
9. Publish: interactive and Folio Security Evidence Records.
10. Operate: invalidate evidence on drift, ingest incidents, repeat.

## Adversarial review
For every boundary ask what happens if identity is forged, input is malicious, authorization is bypassed, a dependency/agent is compromised, storage/network lies, evidence is stale, or a control partially fails.

## Independence
The author may provide evidence but cannot be sole verifier for a critical security-sensitive change.

## Negative knowledge
Record not-tested, not-observed, unavailable, stale, contradictory and out-of-scope facts. Unknown is information.

## Gate semantics
BLOCKED: known blocking violation or unreconciled unknown security effect.
INDETERMINATE: required evidence cannot establish posture.
CONDITIONAL: only via valid explicit human-approved exception.
PASS: only the defined in-scope invariants are currently evidenced; it is not a claim of general security.
