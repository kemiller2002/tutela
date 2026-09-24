# Tutela Requirements

Normative baseline for Tutela 0.1.0.

## Governing principles
TUT-0001 MUST never produce an unqualified "secure" assertion.
TUT-0002 Every security conclusion MUST declare scope, evidence, freshness, and unresolved unknowns.
TUT-0003 Unknown security effects MUST be first-class and MUST block release until reconciled or covered by an authorized, expiring exception.
TUT-0004 Absence of detected findings MUST NOT be treated as proof of absence.
TUT-0005 Security state MUST be derived from artifacts, not prose-only judgment.
TUT-0006 The agent implementing a security-sensitive change MUST NOT be its sole independent verifier.
TUT-0007 Security controls MUST fail closed where failure could grant capability or release unsafe state.

## Assets
TUT-0101 Projects MUST inventory credentials, identities, source, artifacts, data, configuration, infrastructure, logs, prompts/models, repositories and critical operations.
TUT-0102 Assets MUST record owner, classification and confidentiality/integrity/availability needs.
TUT-0103 Sensitive values MUST NOT appear in evidence artifacts; redacted references MUST be supported.

## Boundaries and flows
TUT-0201 Every external, identity, browser, WASM, agent, storage and network boundary MUST be identified.
TUT-0202 Crossings MUST identify data, direction, mechanism, authentication, authorization, validation and trust assumptions.
TUT-0203 Untrusted input MUST remain untrusted until an evidenced validation/sanitization transition.
TUT-0204 Boundary diagrams MUST trace to the model.

## Identity and authorization
TUT-0301 Authentication and authorization MUST be modeled separately.
TUT-0302 Privileged actions MUST require explicit least-privilege capabilities.
TUT-0303 Authorization MUST be checked at the external-effect boundary.
TUT-0304 Capability delegation, expiry, revocation and scope MUST be modeled where applicable.
TUT-0305 Cross-tenant/organization access MUST have isolation invariants and negative tests.
TUT-0306 Default authorization posture MUST be deny.

## Secrets and cryptography
TUT-0401 Secrets MUST NOT be committed, logged, rendered, embedded in client artifacts, or placed in evidence.
TUT-0402 Credential scope, storage, rotation/revocation and exposure response MUST be documented.
TUT-0403 Established cryptographic primitives MUST be used; custom cryptography requires explicit review.
TUT-0404 Encryption requirements MUST distinguish transit, rest and application-level needs.

## Threat modeling
TUT-0501 Material assets/boundaries MUST be considered for spoofing, tampering, audit gaps, disclosure, denial of service, privilege escalation and domain abuse.
TUT-0502 Threats MUST record preconditions, attack path, assets, impact, mitigations, evidence and residual unknowns.
TUT-0503 Abuse cases MUST include malicious authenticated users, compromised dependencies, agents/tools, repository content and partial failures.
TUT-0504 Threat models MUST refresh when boundaries/capabilities materially change.

## Security invariants
TUT-0601 Security requirements SHOULD be invariants or forbidden transitions where possible.
TUT-0602 Invariants MUST have stable ID, scope, rationale, verification method and evidence.
TUT-0603 States MUST be Verified, Violated, Unknown, NotApplicable or Stale.
TUT-0604 Contradictory evidence MUST prevent Verified.
TUT-0605 Evidence freshness/expiry MUST be supported.

## Agent and AI security
TUT-0701 External/repository/user content MUST NOT become agent instructions merely because it contains imperative text.
TUT-0702 Tool use MUST be capability-scoped; agents MUST NOT self-grant capabilities.
TUT-0703 High-impact actions MUST support human approval policy.
TUT-0704 Prompt injection, indirect injection, tool-result/context poisoning, evidence fabrication, cross-agent contamination and confused-deputy attacks MUST be modeled.
TUT-0705 Secrets SHOULD be withheld from agent context unless narrowly required.
TUT-0706 Agent evidence MUST record actor/model/tool, input references, method and corroboration requirements.
TUT-0707 Agents MUST NOT weaken policy/gates then use the weakened gate to certify the same change without independent authorization.

## Application security
TUT-0801 Validation, encoding, injection, serialization, path handling, SSRF/egress, CSRF where relevant, sessions/tokens, error leakage and redirects MUST be considered.
TUT-0802 APIs MUST define authentication, authorization, abuse controls, validation and errors.
TUT-0803 Browser applications MUST define browser security assumptions/CSP where applicable.
TUT-0804 Limen applications MUST model JS/WASM/DOM/network/storage boundaries.
TUT-0805 Logs/telemetry MUST be reviewed for sensitive-data leakage.

## Supply chain
TUT-0901 Direct/transitive dependencies MUST be inventoried.
TUT-0902 New dependencies MUST have justification.
TUT-0903 CI/CD permissions MUST use least privilege.
TUT-0904 Third-party actions SHOULD be immutably pinned with provenance.
TUT-0905 SBOM/provenance/signing MUST be supported where warranted.
TUT-0906 Unexpected binaries/generated artifacts MUST be surfaced.
TUT-0907 Dependency/workflow changes MUST trigger review.

## Verification
TUT-1001 Evidence MAY come from tests, Aegis, static/dependency/secret/config analysis, fuzzing, manual/adversarial review and runtime observation.
TUT-1002 Scanner output MUST be evidence, not the conclusion.
TUT-1003 Fixed defects MUST be eligible for regression tests.
TUT-1004 Critical authorization/isolation invariants SHOULD use negative/property tests.
TUT-1005 Verification MUST record immutable ref and environment.
TUT-1006 Security-sensitive changes MUST identify independent verification.

## Findings and exceptions
TUT-1101 Findings MUST record severity, exploit preconditions, affected invariant/assets, evidence, remediation and state.
TUT-1102 Severity MUST NOT be the sole gate; violated invariants/unknown effects take precedence.
TUT-1103 Accepted risk MUST be an explicit human decision.
TUT-1104 Exceptions MUST record approver, rationale, scope, compensating controls, evidence, creation and expiry.
TUT-1105 Expired exceptions MUST cease satisfying gates.

## Release gates
TUT-1201 Postures MUST be PASS, CONDITIONAL, BLOCKED or INDETERMINATE.
TUT-1202 BLOCKED: unresolved blocking violations or unknown security effects.
TUT-1203 INDETERMINATE: required evidence missing/stale/contradictory enough that posture cannot be established.
TUT-1204 CONDITIONAL requires valid human-approved exceptions.
TUT-1205 PASS means only in-scope invariants have sufficient current evidence with no blocking unknowns/findings.
TUT-1206 Release evidence MUST bind to immutable commit/artifact identity.

## Operations
TUT-1301 Runtime assumptions, audit events and detection expectations MUST be documented.
TUT-1302 Credential compromise and security finding response paths MUST be defined.
TUT-1303 Incidents MUST feed threats/invariants/regression evidence.
TUT-1304 Post-release drift MUST invalidate evidence or create unknowns.

## Integrations
TUT-1401 Ordo/SDE owns legal state/transition/capability semantics; Tutela adds security invariants.
TUT-1402 ROS manages security work, evidence lifecycle and obligations.
TUT-1403 Aegis observations map to Tutela findings/evidence with provenance.
TUT-1404 Praxis tracks security metrics/trends without a misleading single score.
TUT-1405 Folio MUST support a Security Evidence Record.
TUT-1406 Forma MUST support accessible interactive security results.
TUT-1407 Conditor SHOULD install/update Tutela.
TUT-1408 Integrations MUST preserve source provenance.

## Results UI
TUT-1501 Lead with posture, scope, immutable ref, freshness and blockers.
TUT-1502 Distinguish states without color alone.
TUT-1503 Drill down posture -> invariant/threat/finding -> evidence -> source.
TUT-1504 Unknowns MUST have equal prominence to findings.
TUT-1505 Show evidence age/invalidation reason.
TUT-1506 Support keyboard, screen readers, zoom/reflow, reduced motion, high contrast and mobile.
TUT-1507 MUST NOT use a single numeric security score as primary representation.
TUT-1508 SHOULD show recurring findings, boundary changes, evidence/exception aging and security-sensitive churn.
TUT-1509 Print output MUST retain IDs, states, evidence, scope and unknowns.
TUT-1510 Sensitive evidence MUST be redacted by default.

## Governance
TUT-1601 Policy changes MUST be auditable.
TUT-1602 Gate weakening MUST require authorization and be surfaced as security-significant.
TUT-1603 Evidence/decisions MUST remain traceable; destructive history rewriting MUST NOT be required.
TUT-1604 Machine schemas MUST be versioned with migration policy.
