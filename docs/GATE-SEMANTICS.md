# Gate Semantics

Tutela derives posture. Callers do not choose it.

Precedence:
1. Malformed or contradictory assessment -> INDETERMINATE.
2. Unaccepted violated invariant or unknown security effect -> BLOCKED.
3. Unknown/stale required invariant state -> INDETERMINATE.
4. A condition covered only by a current explicit human-approved exception -> CONDITIONAL.
5. Otherwise -> PASS.

PASS is scoped evidence status, not a claim that software is generally secure.

The executable reference is `src/tutela_gate.py`. It intentionally uses only the Python standard library so the security gate does not introduce a dependency merely to evaluate its own state.
