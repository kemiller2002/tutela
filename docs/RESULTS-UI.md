# Tutela Results UI

The UI answers, in order: Can this release proceed? Why? What do we know? What do we not know? What evidence supports it?

## Primary screen
- Header: repository, release/commit, assessment time, freshness, scope.
- Posture banner: PASS / CONDITIONAL / BLOCKED / INDETERMINATE using text/icon/pattern, never color alone.
- Blockers: violated invariants, unknown effects, stale required evidence, expired exceptions.
- State matrix: Verified / Violated / Unknown / Stale / N/A counts. No composite security score.
- Domains: Identity, Authorization, Secrets, Data, Boundaries, Agent/AI, Application, Supply Chain, Build/CI, Runtime/Operations.
- Change panel: security-sensitive files, boundaries and capabilities changed since prior assessment.
- Trend panel: recurring/reopened findings, evidence aging, exception aging and Praxis hotspot/churn metrics.

## Drill-down
Invariant: ID, statement, state, scope, rationale, threats, controls, evidence, contradictions, freshness, owner.
Threat: attack path, preconditions, assets/boundaries, mitigations, residual unknowns.
Evidence: type/source, immutable ref/hash, producer, time, environment, method, independence, redaction, expiry.
Unknown: what, why, consequence, evidence needed, owner/obligation.
Exception: approver, scope, rationale, compensating controls, creation/expiry.

## Interaction/accessibility
Filter by domain/state/severity/evidence age/boundary; stable-ID search; shareable deep links; keyboard-first controls; accessible tables; mobile cards; Folio export. Status never relies on color. Respect reduced motion, high contrast, reflow and zoom.

## Forma component candidates
- ef-security-posture
- ef-security-state-matrix
- ef-security-blockers
- ef-invariant-result
- ef-threat-path
- ef-evidence-chain
- ef-unknown-result
- ef-exception-status
- ef-evidence-age
- ef-security-trend
- ef-boundary-map

## Folio print structure
Cover/posture; scope; blockers; invariant matrix; threats/findings; unknowns; exceptions; evidence index; methodology/limitations; immutable release identity.
