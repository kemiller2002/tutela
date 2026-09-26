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

## Shared Echelon application foundations

TUT-1701 Tutela runtime/tooling that owns a .NET/F# operational boundary MUST use Aegis for unexpected external failure. Expected security findings, violated invariants, unknown security effects, denied capabilities, and release-gate outcomes MUST remain Tutela/Ordo domain states and MUST NOT be converted into Aegis faults.

TUT-1702 Aegis MAY provide security-relevant observations/evidence to Tutela with provenance, but Aegis MUST NOT become the authority that decides security posture. Tutela remains the security authority.

TUT-1703 Interactive Tutela results UI MUST consume a pinned Forma release and existing Forma patterns/components before local equivalents. Accessibility, keyboard, mobile, non-color-state, and responsive contracts MUST be preserved.

TUT-1704 Printable/PDF/paginated Security Evidence Records, posture reports, findings reports, exception records, or other security documents MUST consume a pinned Folio release and use existing Folio primitives before local print implementations.

TUT-1705 Forma owns interactive presentation; Folio owns reusable document/print intent; Aegis owns unexpected operational-fault capture; Tutela owns security meaning, evidence interpretation, invariants, findings, exceptions, and posture.

TUT-1706 Shared dependencies MUST be pinned to released versions or immutable artifacts. A shared capability gap MUST be recorded in the owning shared repository rather than silently forked inside Tutela.

## Praxis contribution provenance

Praxis owns the agent identity and provenance model (Praxis DF-ROS-2026-A036, DF-ROS-2026-A037). Tutela carries it; it does not redefine it. On Tutela evidence, `provenance` already means issuer/run attestation, so Praxis contribution provenance is carried under the separate field `contributionProvenance`.

TUT-1707 Evidence records and security assessments MAY carry `contributionProvenance`: a Praxis `praxis.provenance/1` interchange block (Praxis RQ-ROS-2026-A015, DF-ROS-2026-A037) stating who reports having discovered, remediated, measured, validated, reviewed or transformed the subject, and in which execution. Tutela MUST NOT redefine actor, execution, contribution, operation or unknown semantics, and MUST NOT copy-and-modify the Praxis schemas; it references unchanged vendored copies recorded with source commit and SHA-256.

TUT-1708 `contributionProvenance` is self-reported and non-authoritative (Praxis RQ-ROS-2026-A010, RQ-ROS-2026-A019). It MUST NOT satisfy, substitute for, or influence `producerIdentity`, evidence `provenance` (issuer/run attestation), evidence authority (security/PROVENANCE-AUTHORITY.json), identity bindings, approver or verifier identity, role membership or authorization (security/ROLE-REGISTRY.json), verifier independence (TUT-0006, TUT-1006), or evidence weight. The derived posture and every gate reason MUST be identical with and without it, including when it claims that a registered approver or verifier acted; the only permitted effect is the existing fail-closed sensitive-field check over evidence, which can lower posture but never raise it. It MAY satisfy the descriptive recording part of TUT-0706 (actor/model/tool) but never its corroboration part.

TUT-1709 A received block MUST be classified with the Praxis receiving rules (Praxis RQ-ROS-2026-A015): `supported` blocks MUST be preserved verbatim, including unknown fields and tolerated unknown operation codes; a block of another major version (`unsupported`) MUST be preserved verbatim and MUST NOT be interpreted or appended to; a `malformed` block MUST make the carrying record invalid and MUST be rejected before any record is written, never dropped or repaired silently. Records without `contributionProvenance` remain valid and read as unattributed; nothing is inferred or backfilled (TUT-1603).

TUT-1710 `contributionProvenance` MUST NOT carry secrets (Praxis RQ-ROS-2026-A017, TUT-0103, TUT-0401). Any credential-like value anywhere in the block, including in an unsupported major version, makes it malformed.

TUT-1711 Integrations that supply `contributionProvenance` (for example the Aegis `tutela/evidence/v1` projection) MUST have it preserved verbatim (TUT-1403, TUT-1408). Tutela MUST NOT re-attribute a contribution, replace an originator, or overwrite the original actor with the transporting actor; any appending MUST follow the Praxis append-only rules (Praxis RQ-ROS-2026-A004, RQ-ROS-2026-A015).

TUT-1712 The Tutela codec MUST reach the reference verdict and warning count for every vendored Praxis conformance case and replay the Echelon end-to-end chain (Praxis RQ-ROS-2026-A018). Adding `contributionProvenance` to the machine schemas MUST be additive and optional so existing documents stay valid (TUT-1604). Because `schemas/evidence.schema.json` and `schemas/security-assessment.schema.json` are protected trust-root paths, that schema change requires independent approval evidence before release (TUT-0006, TUT-0707, TUT-1602).

### Traceability

| Requirement | Implementation | Verification |
|---|---|---|
| TUT-1707 | `schemas/evidence.schema.json` `$defs/contributionProvenance`; `schemas/security-assessment.schema.json` `contributionProvenance`; `schemas/vendor/praxis/` (+ `SOURCE.json`) | `tests/test_tutela_contribution_provenance.py` (VendoredSourceTests, TutelaBoundaryTests) |
| TUT-1708 | Gate unchanged: `src/tutela_gate.py` makes no decision from the field (only its existing fail-closed sensitive-field scan sees it); `src/tutela_contribution_provenance.py` performs no identity, role or authority decision | `tests/test_tutela_gate_contribution_provenance.py`; `tests/fixtures/adversarial/self-reported-approver-provenance.json` |
| TUT-1709 | `src/tutela_contribution_provenance.py` (`classify`, `accept`, `attach`, `read`, `record_problems`, `assessment_problems`); `src/tutela_evidence.py --contribution-provenance` | `tests/test_tutela_contribution_provenance.py` (ConformanceTests, TutelaBoundaryTests, EvidenceBuilderTests) |
| TUT-1710 | `src/tutela_contribution_provenance.py` credential tripwire | `tests/test_tutela_contribution_provenance.py` (`test_credentials_are_never_carried`, credential cases) |
| TUT-1711 | `src/tutela_contribution_provenance.py` (`append_contribution`, `preservation_violations`); `docs/INTEGRATIONS.md` Aegis | `tests/test_tutela_contribution_provenance.py` (AppendingTests, EchelonChainTests) |
| TUT-1712 | `tests/fixtures/praxis-provenance/` (+ `SOURCE.json`); `docs/INTEGRATIONS.md` pending trust-root change | `tests/test_tutela_contribution_provenance.py` (all 40 cases, chain replay, SHA-256 checks) |
