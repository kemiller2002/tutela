# Tutela Self Security Profile

## Assets
Security requirements/policy; schemas/gate logic; evidence/assessments; repository history; CI configuration.

## Trust boundaries
Human/agent; repository content/agent instructions; GitHub/CI runner; third-party actions/dependencies; evidence producer/consumer.

## Foundation invariants
SEC-INV-001 An agent cannot unilaterally weaken a security gate and certify the same change.
SEC-INV-002 Unknown security effects block PASS.
SEC-INV-003 Every posture traces to immutable subject identity and evidence.
SEC-INV-004 Sensitive evidence is redacted by default.
SEC-INV-005 Expired exceptions cannot satisfy a gate.

## Initial threats
SEC-THR-001 Hostile repository text redirects an agent.
SEC-THR-002 Fabricated/stale evidence produces incorrect PASS.
SEC-THR-003 Policy is weakened in the same change being evaluated.
SEC-THR-004 Dependency/workflow compromise changes assessment behavior.
SEC-THR-005 Secret appears in evidence/export.
