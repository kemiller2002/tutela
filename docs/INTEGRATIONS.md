# Integration Contracts

## Ordo/SDE
Security invariants constrain legal states/transitions. Unknown effects block established security knowledge. Preserve negative knowledge.

## ROS
Security work is obligations plus evidence. Completion requires reconciliation, not checkbox completion.

## Aegis
Aegis observations enter as provenance-preserving evidence. Tutela determines invariant state/posture; Aegis does not certify.

Evidence path: Aegis emits a `tutela/evidence/v1` projection shaped as a Tutela evidence record (`schemas/evidence.schema.json`, `type: "Aegis"`). The projection MAY carry `contributionProvenance`, a Praxis `praxis.provenance/1` block recording who discovered, remediated, validated or reviewed the finding and in which execution (TUT-1707, TUT-1711). Tutela:

1. checks the block with `src/tutela_contribution_provenance.py` (`python src/tutela_contribution_provenance.py <evidence-or-assessment.json>`): `supported` and `unsupported` blocks are kept verbatim; a `malformed` block (including any credential-like value) makes the evidence record invalid (TUT-1709, TUT-1710);
2. never re-attributes Aegis's contributions or replaces them with the transporting actor (TUT-1711);
3. never lets the block stand in for `producerIdentity`, the issuer/run `provenance` attestation, identity bindings, approver/verifier identity, role membership or independence (TUT-1708).

Known gap (follow-up, requires trust-root approval): `security/PROVENANCE-AUTHORITY.json` has no authority rule for evidence type `Aegis`, so the gate currently rejects every Aegis evidence record as `provenance issuer is not authorized for evidence type and producer identity` and the assessment derives INDETERMINATE. That is the correct fail-closed behaviour until an authority rule (which issuer, provenance kind and producer identity types may produce `Aegis` evidence) is added. `security/PROVENANCE-AUTHORITY.json` is a protected trust root; the rule MUST be proposed as a trust-root change with independent approval evidence and has deliberately not been added here. `contributionProvenance` cannot close this gap.

## Praxis
Track invariant states, unknown effects, evidence age, exception age, recurring findings, security-sensitive churn and hotspots. No single security score.

Contribution provenance: Praxis owns the actor/execution/contribution model (Praxis DF-ROS-2026-A036, DF-ROS-2026-A037). Evidence records and assessments MAY carry it as `contributionProvenance` (TUT-1707-TUT-1712); the field name is namespaced because `provenance` on Tutela evidence already means issuer/run attestation.

- Schema: `schemas/evidence.schema.json#/$defs/contributionProvenance` references the unchanged vendored `schemas/vendor/praxis/provenance-interchange.schema.json` and `provenance-actor.schema.json` (Praxis contract revision 1.1; source commit and SHA-256 in `schemas/vendor/praxis/SOURCE.json`), or accepts any object tagged with another `praxis.provenance/<major>`, which is carried verbatim. JSON Schema is only the structural floor; the full receiving rules are in `src/tutela_contribution_provenance.py`, tested against every vendored Praxis case (`tests/fixtures/praxis-provenance/`).
- Producing: `python src/tutela_evidence.py ... --contribution-provenance block.json` validates the block before writing and refuses malformed blocks. The current actor is never guessed; only an explicit block is attached.
- Authority: identity recorded there is self-reported (Praxis RQ-ROS-2026-A010, RQ-ROS-2026-A019). Authenticated identity remains `IdentityBinding` (`src/tutela_identity.py`), authorization remains `security/ROLE-REGISTRY.json` and `security/TRUST-ROOT-CHANGE.json`, and evidence authority remains `security/PROVENANCE-AUTHORITY.json`. `tests/test_tutela_gate_contribution_provenance.py` proves the gate's decision is unchanged when the block claims a registered security-owner approved or independently verified a change.
- Metrics: Praxis MAY read `contributionProvenance` to attribute discovery/remediation/validation work in security metrics (TUT-1404); such attribution is descriptive, not a security signal.

Pending trust-root change: adding the optional `contributionProvenance` property touches the protected paths `schemas/evidence.schema.json` (sha256 `8b036168540175f9a47f3b832a48f1fe56805c27278f64caae785e6f3bdffdc4` -> `4a8a41f6e3ed5fb6a07ac4f373cc5842e4141db9f863cb3cd789428add0a37e9`) and `schemas/security-assessment.schema.json` (`a582b0b755276ccafba4b206b11302f38221ef5a4efa73b9b3b6e8ea7e833806` -> `1bdaab1ddac2c0bea3e8c5a9d9805af109fb88f25feedb2a2175939ec5f00dbe`). The protected schemas reference the vendored `schemas/vendor/praxis/provenance-interchange.schema.json`, so its content is part of the effective protected contract: it moved from Praxis a42c44e (sha256 `e7cc8355484025da07b8f2c01e9601331de1657df15eae2a7578417283f329b8`) to contract revision 1.1 at c2657ef (sha256 `33c11f4582040103f6415b5a18e017bea0c674f96d8f36fd08165bb73e9f4b80`; description text only, no structural change); `provenance-actor.schema.json` is unchanged (`f64a7f1c61c0c5b5c46a2d2ae8aebc78e177dc03e4b7c1f3e800e82bcb02b845`). The two protected files' own digests above are unchanged by the re-vendoring. The approver should review the protected files together with the vendored schemas they reference. It was authored by an agent and is not self-approved: it requires independent approval evidence from a registered role before release (TUT-0006, TUT-0707, TUT-1712). Whether widening a closed schema with a non-authoritative field counts as weakening is for the approver to decide.

## Forma
Implement RESULTS-UI components. UI consumes assessment artifacts and does not independently recompute security truth.

## Folio
Render the same model into an immutable Security Evidence Record, preserving limitations and unknowns.

## Limen
Inventory JS/WASM/DOM/network/storage crossings and capabilities for browser/WASM systems.

## Conditor
Install/update Tutela manifest, schemas, baseline policy, gate workflow and project security profile idempotently.
