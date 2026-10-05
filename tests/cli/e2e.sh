#!/usr/bin/env bash
# End-to-end checks of the built F# CLI (the gate authority):
#  1. differential: for every committed assessment the CLI's legacy envelope
#     and exit code equal the Python conformance oracle's;
#  2. contract: `gate` emits tutela.verification/1 with the documented exit codes;
#  3. error paths: unreadable input is `unavailable` (3), malformed JSON is
#     INDETERMINATE (1), usage errors and declared-posture mismatch are 2.
# Usage: tests/cli/e2e.sh [path/to/tutela.dll]   (run from the repository root)
set -uo pipefail
dll="${1:-src/Tutela.Cli/bin/Release/net10.0/tutela.dll}"
tutela() { dotnet "$dll" "$@"; }
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
failures=0; checks=0
expect() { # name expected actual
  checks=$((checks+1))
  if [ "$2" != "$3" ]; then echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures+1)); fi
}
canon() { python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin),sort_keys=True))'; }

for f in examples/*.json assessments/*.json tests/fixtures/adversarial/*.json; do
  fs="$(tutela "$f" --check-declared 2>/dev/null | canon)"; fe=${PIPESTATUS[0]}
  ps="$(python3 src/tutela_gate.py "$f" --check-declared 2>/dev/null | canon)"; pe=${PIPESTATUS[0]}
  expect "differential-output $f" "$ps" "$fs"
  expect "differential-exit $f" "$pe" "$fe"
done

tutela gate examples/security-assessment.json --check-declared --output "$work/v.json"; expect "gate-blocked-exit" 1 $?
expect "contract-schema" "tutela.verification/1" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["schema"])' "$work/v.json")"
expect "contract-verdict" "blocked" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' "$work/v.json")"

python3 - "$work" <<'PY'
import json, sys, pathlib
work = pathlib.Path(sys.argv[1])
a = json.loads(pathlib.Path("examples/security-assessment.json").read_text())
a["posture"] = "PASS"; (work / "mismatch.json").write_text(json.dumps(a))
p = {"schemaVersion": 1, "subject": {"repository": "x/y", "ref": "abc"}, "posture": "PASS",
     "invariantResults": [{"id": "SEC-INV-001", "state": "NotApplicable", "evidence": []}], "unknownSecurityEffects": []}
(work / "pass.json").write_text(json.dumps(p))
(work / "malformed.json").write_text("{not json")
PY
tutela gate "$work/pass.json" --check-declared >/dev/null; expect "gate-pass-exit" 0 $?
tutela gate "$work/mismatch.json" --check-declared >/dev/null 2>&1; expect "declared-mismatch-exit" 2 $?
tutela gate "$work/malformed.json" >/dev/null; expect "malformed-exit" 1 $?
tutela gate "$work/missing.json" >/dev/null 2>&1; expect "unavailable-exit" 3 $?
tutela gate examples/security-assessment.json --policy-root "$work" >/dev/null 2>&1; expect "missing-policy-unavailable-exit" 3 $?
tutela gate >/dev/null 2>&1; expect "usage-exit" 2 $?
tutela gate examples/security-assessment.json --at not-a-time >/dev/null 2>&1; expect "bad-at-exit" 2 $?

printf 'x = "%s%s"\n' "AKIA" "ABCDEFGHIJKLMNOP" > "$work/leak.txt"
tutela scan-secrets --root "$work" leak.txt --catalog security/SENSITIVE-DATA-RULES.json --output "$work/scan.json" 2>/dev/null; expect "scan-finding-exit" 1 $?
expect "scan-redacts-value" "0" "$(grep -c ABCDEFGHIJKLMNOP "$work/scan.json")"

echo "CLI end-to-end: $checks checks, $((checks-failures)) passed, $failures failed"
[ "$failures" -eq 0 ]
