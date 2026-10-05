# Gate Semantics

Tutela derives posture. Callers do not choose it.

Precedence:
1. Malformed or contradictory assessment -> INDETERMINATE.
2. Unaccepted violated invariant or unknown security effect -> BLOCKED.
3. Unknown/stale required invariant state -> INDETERMINATE.
4. A condition covered only by a current explicit human-approved exception -> CONDITIONAL.
   "Human-approved" is checked, not claimed. The approver must be a verified human
   identity, must differ from the requester, and must hold `security-owner` in
   `security/ROLE-REGISTRY.json` at evaluation time. Expired, self-approved or
   unregistered approvals are rejected, and the covered condition keeps its
   BLOCKED or INDETERMINATE effect (see docs/VERIFICATION-CONTRACT.md).
5. Otherwise -> PASS.

PASS is scoped evidence status, not a claim that software is generally secure.

The executable authority is the F# gate (`src/Tutela.Core`, CLI `src/Tutela.Cli`). It depends only on the .NET base class library, so the security gate does not take on a dependency just to evaluate its own state. Its machine-readable output is `tutela.verification/1` (docs/VERIFICATION-CONTRACT.md).

`src/tutela_gate.py` is a conformance oracle kept under the expiring migration bridge in docs/decisions/0001-gate-authority.md. CI requires both implementations to agree exactly on `tests/parity/corpus.json` and on every committed assessment.
