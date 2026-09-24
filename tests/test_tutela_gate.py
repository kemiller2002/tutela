import unittest
from datetime import datetime, timezone
from src.tutela_gate import derive, validate

def assessment(state="Verified", evidence=None, unknown=None, exceptions=None):
    return {"schemaVersion":1,"subject":{"repository":"x/y","ref":"abc123"},"posture":"PASS",
      "invariantResults":[{"id":"SEC-INV-001","state":state,"evidence":evidence if evidence is not None else ["SEC-EVD-001"]}],
      "unknownSecurityEffects":unknown or [],"exceptions":exceptions or []}

class GateTests(unittest.TestCase):
    def test_pass(self): self.assertEqual("PASS",derive(assessment())[0])
    def test_violation_blocks(self): self.assertEqual("BLOCKED",derive(assessment("Violated"))[0])
    def test_unknown_effect_blocks(self): self.assertEqual("BLOCKED",derive(assessment(unknown=["SEC-UNK-001"]))[0])
    def test_unknown_invariant_indeterminate(self): self.assertEqual("INDETERMINATE",derive(assessment("Unknown"))[0])
    def test_stale_indeterminate(self): self.assertEqual("INDETERMINATE",derive(assessment("Stale"))[0])
    def test_verified_requires_evidence(self): self.assertTrue(validate(assessment(evidence=[])))
    def test_contradiction_invalid(self):
        a=assessment(); a["invariantResults"][0]["contradictoryEvidence"]=["SEC-EVD-002"]
        self.assertEqual("INDETERMINATE",derive(a)[0])
    def test_valid_exception_is_conditional(self):
        e={"id":"SEC-EXC-001","approver":"human","approved":True,"expiresAt":"2099-01-01T00:00:00Z","covers":["SEC-INV-001"]}
        self.assertEqual("CONDITIONAL",derive(assessment("Violated",exceptions=[e]),datetime(2026,1,1,tzinfo=timezone.utc))[0])
    def test_expired_exception_blocks(self):
        e={"id":"SEC-EXC-001","approver":"human","approved":True,"expiresAt":"2020-01-01T00:00:00Z","covers":["SEC-INV-001"]}
        self.assertEqual("BLOCKED",derive(assessment("Violated",exceptions=[e]),datetime(2026,1,1,tzinfo=timezone.utc))[0])
    def test_duplicate_invariant_invalid(self):
        a=assessment(); a["invariantResults"].append(dict(a["invariantResults"][0]))
        self.assertEqual("INDETERMINATE",derive(a)[0])

if __name__=="__main__": unittest.main()
