# 0001: The F# gate is the CI authority; Python stays as an expiring conformance bridge

- Status: accepted by the implementing change, pending owner acknowledgement (see Ownership)
- Date: 2026-10-05
- Requirements: TUT-1801, TUT-1803, TUT-1804, TUT-1807; AGENTS.md rules 11-13
- Expires: 2027-01-31 (CI fails after this date while `src/tutela_gate.py` still exists)

## Context

AGENTS.md rules 11-13 and TUT-1801/TUT-1804 name F# as the single implementation
authority. In practice CI derived release posture with `src/tutela_gate.py`, the F#
CLI did not compile, and CI built only `Tutela.Core`. The F# `validate` checked two
rules while the Python gate checked about twenty. Run against the adversarial
fixtures, the F# gate derived PASS for 6 of the 8 that Python rejects (fabricated
evidence, gate weakening, missing independent review, producer impersonation,
secret leakage, wrong-commit evidence). The declared authority was therefore not
the effective authority, and it would have failed open.

TUT-1804 allows Python to act as a conformance oracle "until equivalent F#
behavior has evidence", after which "production execution and CI authority MUST
use the F# implementation".

## Decision

1. **The F# CLI (`src/Tutela.Cli`, assembly `tutela`) is the gate CI runs.** It
   derives release posture and publishes `tutela.verification/1`. The CI steps
   "Verify example posture" and "Verify self-assessment postures" use it.
2. **The Python gate is a conformance oracle, not a gate.** It is no longer
   consulted for any posture decision in CI. It runs only to:
   - reproduce the shared parity corpus (`tests/parity/corpus.json`), and
   - be compared with the F# CLI on every committed assessment (`tests/cli/e2e.sh`).
   Any disagreement fails CI.
3. **Equivalence evidence.** The F# port reproduces the oracle's posture and its
   exact reason strings on every case of the 83-case corpus, and on all 11
   committed assessments end to end. Where the oracle would crash, the F# gate
   fails closed instead: a non-object document, a non-array
   `unknownSecurityEffects`, a naive timestamp, or an unreadable `validUntil`
   gives INDETERMINATE, and missing policy gives `unavailable`. These cases
   strengthen behavior and are allowed by TUT-1807.
4. **New security behavior goes into F# first.** A Python change is allowed only
   to keep the oracle comparable (AGENTS.md rule 12). This change added two such
   oracle changes: exception approval binding (TUT-F3) and loading the
   sensitive-data catalog.

## Bridge scope

These non-F# executables still run in CI. All are inside this bridge:

| Executable | Role | Retirement |
|---|---|---|
| `src/tutela_gate.py` | conformance oracle | delete together with `tests/test_tutela_parity.py`; freeze `tests/parity/corpus.json` as F#-only expectations |
| `src/tutela_trust_root.py` | CI trust-root transition check | port to `tutela trust-root` (issue #3, item 6); the port must keep the base-and-head protected-set union, removal coverage and base-policy approval authority recorded in TR-2026-0004, and the per-record validation, union coverage and immutability of merged records recorded in TR-2026-0005 |
| `src/tutela_evidence.py`, `tutela_identity.py` | evidence / identity-binding producers | port (issue #3, items 5 and 7) |
| `src/tutela_present.py`, `tutela_render.py` | presentation projection | port, or move to Forma/Folio per TUT-1703/1704 |
| `bin/tutela.mjs` | Conditor lifecycle installer | tracked by issue #6 (native distribution) |

## Retirement condition

The bridge ends, and Python is removed from CI, when **all** of these hold:

1. An **independent** verifier has reviewed and attested to the F# gate port. The
   implementing agent may not self-certify (TUT-0006, AGENTS.md rule 4).
2. The trust-root, evidence and identity producers in the table above have F#
   equivalents with tests.
3. The parity corpus expectations have moved into the F# test suite, and nothing
   depends on the Python gate.

## Ownership and expiry

- Owner: the Tutela repository owner (`kemiller2002`), who holds the security-owner
  role for this decision. The implementing agent recorded the decision and cannot
  accept it on the owner's behalf. The owner acknowledges it by merging.
- Expiry: 2027-01-31. CI step "Migration bridge expiry" fails after that date while
  `src/tutela_gate.py` exists. Extending the date needs a new dated revision of
  this record, with rationale.

## Consequences

- An F#-only behavior change without a matching oracle change fails parity. This
  is intended: the oracle must be updated deliberately, or the bridge retired.
- `docs/GATE-SEMANTICS.md` now names the F# gate as the executable reference.
