# Adversarial Application Testing

Tutela treats hostile runtime behavior as security evidence, not as a separate security verdict.

## Campaign model

A campaign binds to an immutable subject and environment and contains attack scenarios. Each scenario records:

Attack -> expected invariant -> observation -> state impact -> data impact -> recovery -> evidence.

Outcomes are deliberately descriptive:

- RESISTED: the attempted hostile behavior did not violate the expected invariants.
- DEGRADED_SAFE: capability or availability degraded, but the tested invariants and data integrity were preserved.
- VIOLATED: at least one expected invariant was violated.
- INDETERMINATE: available evidence cannot establish the outcome.
- NOT_RUN: planned coverage was not executed.

These outcomes do not replace Tutela release posture and MUST NOT be collapsed into a numeric security score.

## Minimum campaign families

Campaign planning MUST consider malicious/oversized input; authentication replay/substitution/expiry; authorization and cross-tenant access; illegal/stale/replayed state transitions; malformed protocol/API behavior; resource exhaustion; dependency failure/corruption; concurrency/races/retries; information leakage; recovery after interruption; and agent/tool abuse where applicable.

Not every family applies to every subject. Omitted or inapplicable families require an explicit reason. Untested relevant attack surface is negative knowledge.

## State-system emphasis

For Ordo/SDE applications, hostile callers MUST be used to exercise forbidden transitions, stale versions, replayed commands, contradictory evidence, missing capabilities, duplicate effects, and reordered operations. The key question is whether legal-state guarantees survive malicious sequencing, not merely normal tests.

## Execution safety

Campaigns MUST target an explicitly authorized environment. Destructive, resource-exhaustion, credential, or third-party-impacting scenarios require bounded execution and explicit authorization. Production targets are not implied by campaign configuration.

## Evidence and gating

Scenario evidence SHOULD include immutable subject ref, harness/tool identity, inputs or reproducible generator seed, timestamps, environment, observations, logs/traces where safe, and recovery observations. Sensitive material is redacted.

A VIOLATED outcome maps to a Tutela finding/invariant result as appropriate. INDETERMINATE and NOT_RUN on required coverage remain unknown security knowledge. DEGRADED_SAFE is useful evidence only for the invariants actually exercised.

## Longitudinal metrics

Praxis/Dokimos may track counts and trends such as recurring violations, time-to-recovery, regression/resurfacing, campaign coverage, and evidence age. They MUST preserve the underlying states and MUST NOT present a composite "security score".


## HTTP/API adapter

The first execution adapter uses declarative HTTP requests. An authorization artifact supplies exact allowed origins; the adapter refuses any other origin. Methods, request bytes, response bytes, timeout and campaign attempts are bounded.

The adapter records response status, bounded byte count, truncation state, response digest and redacted headers. It does not preserve response bodies by default. Authorization, cookie, set-cookie and proxy-authorization header values are redacted.

HTTP expectations are invariant observations rather than generic exploit success. A scenario declares acceptable status values and, where meaningful, explicit status values that demonstrate a violated invariant. An unexpected response that has not been declared to prove a violation remains INDETERMINATE rather than being guessed into PASS or FAIL.

Initial campaign patterns SHOULD cover negative authentication, negative authorization/isolation, validation/error behavior, replay/idempotency and information-leakage observations. Concurrency, dependency fault injection and resource-pressure adapters remain separate capabilities because they require additional execution budgets and safety controls.
