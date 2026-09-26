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


## Adversarial campaign view
- Campaign header: immutable subject, authorized environment, scope, execution time and limitations.
- Outcome matrix: RESISTED / DEGRADED_SAFE / VIOLATED / INDETERMINATE / NOT_RUN counts, explicitly descriptive and never a score.
- Attack-family coverage: input, authentication, authorization, state, protocol, resource, dependency, concurrency, information, recovery, and agent/AI where applicable.
- Scenario drill-down: attack -> expected invariant -> observation -> state/data impact -> recovery -> evidence.
- Unknown coverage panel: planned but unrun, indeterminate, omitted relevant surfaces and scenario limitations.
- Regression/trend panel: previously fixed attacks resurfacing, recurring violations, recovery-time change and evidence aging.


### Release-posture integration
Required adversarial outcomes participate directly in the deterministic gate:
- VIOLATED is a release blocker unless covered by a valid explicit exception.
- INDETERMINATE and NOT_RUN are unresolved required knowledge and produce INDETERMINATE posture unless covered by a valid explicit exception.
- RESISTED and DEGRADED_SAFE do not independently lower posture and do not establish security outside the tested invariants.
- Optional NOT_RUN/INDETERMINATE coverage remains visible in the adversarial view but does not become a release blocker merely by being optional.

The presentation projection exposes outcome counts, required blockers, required unknowns, invariant/evidence references, recovery and limitations. UI implementations MUST preserve these distinct states rather than reducing them to pass/fail or a numeric score.
