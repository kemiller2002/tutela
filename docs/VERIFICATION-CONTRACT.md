# Tutela verification contract (`tutela.verification/1`)

Tutela owns this contract. The F# gate produces it, and it is the supported way
for other systems to consume a Tutela verdict. Examples are Praxis telemetry, the
Aegis evidence adapter, Conditor and release pipelines. The schema is
`schemas/verification-result.schema.json`.

## Invocation

```
tutela gate <assessment.json> [--check-declared] [--format verification|legacy]
            [--at <ISO-8601 instant with offset>] [--policy-root <dir>] [--output <path>]
tutela <assessment.json> [--check-declared]      # legacy {derivedPosture, reasons} envelope
tutela scan-secrets [--root <dir>] [--catalog <path>] [--output <path>] [<file>...]
tutela trace [--root <dir>] [--baseline <path>] [--output <path>]
```

From source: `dotnet run --project src/Tutela.Cli -- gate examples/security-assessment.json`.
Policy documents are read from `--policy-root`, which defaults to the working
directory:
- `security/PROVENANCE-AUTHORITY.json`
- `security/TRUST-ROOT-CHANGE.json`
- `security/ROLE-REGISTRY.json`
- `security/SENSITIVE-DATA-RULES.json`

## Exit codes

| Code | Meaning |
|---|---|
| 0 | `pass` or `conditional`; scan clean; traceability within ratchet |
| 1 | `blocked` or `indeterminate`; scan findings; traceability ratchet exceeded |
| 2 | usage error, or `--check-declared` and the declared posture differs from the derived one |
| 3 | `unavailable`: the gate could not evaluate (unreadable assessment, missing or invalid policy, git unavailable for scan/trace) |

Consumers MUST treat any exit code other than 0 as not releasable.

## Fields

| Field | Meaning |
|---|---|
| `schema` | always `tutela.verification/1`; treat anything else as `unavailable` |
| `tool` | `{name: "tutela", version, implementation: "fsharp"}` |
| `evaluatedAt` | UTC instant the posture was derived at (exceptions, evidence expiry and role validity are evaluated at this instant) |
| `assessment` | `{path, sha256}`: binds the verdict to the exact bytes evaluated |
| `subject` | `{repository, ref}` from the assessment, or null |
| `verdict` | `pass` \| `conditional` \| `blocked` \| `indeterminate` \| `unavailable` |
| `posture` | Tutela posture `PASS` \| `CONDITIONAL` \| `BLOCKED` \| `INDETERMINATE`, null when unavailable |
| `reasons` | the deterministic reason list (identical to the legacy envelope) |
| `declaredPosture`, `declaredMatches` | the posture the assessment claims and whether the gate agrees |
| `findings[]` | `{ruleId, severity: blocking\|indeterminate\|advisory, subject, message}` |
| `exceptions[]` | `{id, status: honored\|rejected, covers, expiresAt, rejections: [{code, ruleId}]}` |
| `policies[]` | `{name, path, sha256}` of every policy document the verdict depended on |
| `limitations[]` | scope qualifications; PASS is never a claim that the subject is secure |

`indeterminate` is kept separate from `unavailable`. The first means the gate
evaluated the evidence and could not establish posture (TUT-1203). The second
means the gate did not evaluate at all.

## Stable rule ids

Rule ids are never reused or renumbered. Messages may change; ids do not.

| Id | Rule |
|---|---|
| TUTELA-G001 / G002 | role registry / provenance authority policy must default deny |
| TUTELA-G010 | assessment structure (non-object, wrong member types, unparseable JSON) |
| TUTELA-G011 | `schemaVersion` must be 1 |
| TUTELA-G012 | subject repository and ref required |
| TUTELA-G013 | an assessment cannot authorize gate weakening |
| TUTELA-G014 / G015 / G016 | invariant / threat / exception structure |
| TUTELA-G020 / G021 / G022 | Verified needs evidence / no contradictory evidence / independent verification |
| TUTELA-G030 ... G038 | evidence structure, digest, provenance, issuer authority, subject binding, invalidation, undeclared references, stale evidence, unreadable evidence time |
| TUTELA-G040 | protected trust-root change |
| TUTELA-G100 / G101 | violated invariant / unknown security effect (blocking) |
| TUTELA-G102 / G103 / G104 | unknown / stale / evidence-less invariant (indeterminate) |
| TUTELA-G110 | exception honored |
| TUTELA-G200 ... G210 | exception rejected: not-approved, invalid-expiry, expired, invalid-creation, not-yet-valid, incomplete-record, requester-unbound, approver-unbound, approver-not-human, self-approval, approver-lacks-role |
| TUTELA-G300 | declared posture differs from derived posture |
| TUTELA-G900 | evaluation unavailable |
| TUTELA-SD-K001 ... K007, V001 ... V008 | sensitive-data catalog rules (`security/SENSITIVE-DATA-RULES.json`) |

## Exception approval

An exception can move BLOCKED or INDETERMINATE to CONDITIONAL only when every
one of the following holds at `evaluatedAt`:

- `approved: true`, a parseable offset-qualified `createdAt <= evaluatedAt < expiresAt`;
- non-empty `covers`, `rationale`, `compensatingControls` and `evidence` (TUT-1104);
- `requestedByIdentity` and `approverIdentity` are verified platform bindings
  (provider + immutable numeric subject id + platform evidence; logins confer nothing);
- the approver is a **human**, is **not the requester** (same provider and
  subject id is self-approval, whatever the login), and holds **security-owner** in
  `security/ROLE-REGISTRY.json` at `evaluatedAt`. Role claims inside the assessment
  are not authoritative.

The registry currently has no memberships, so no exception can be honored until
the owner records one. This is deliberate fail-closed behavior. Rejected
exceptions are reported with their codes and never silently ignored.

## Versioning

New optional fields may be added within `/1`. Removing a field, changing its
meaning, or adding a verdict value requires `tutela.verification/2`, published
alongside `/1` for at least one release (TUT-1604).
