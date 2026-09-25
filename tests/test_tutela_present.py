import unittest
from src.tutela_present import project

class ProjectionTests(unittest.TestCase):
    def test_projection_derives_posture_instead_of_trusting_declared_value(self):
        a={"schemaVersion":1,"assessmentId":"A1","subject":{"repository":"x/y","ref":"abc"},"posture":"PASS",
           "invariantResults":[{"id":"SEC-INV-001","state":"Unknown","evidence":[]}],"unknownSecurityEffects":[],"exceptions":[]}
        view=project(a)
        self.assertEqual("INDETERMINATE",view["posture"])
        self.assertIn("not a general claim",view["qualification"])

    def test_projection_preserves_provenance_for_drilldown(self):
        e={"id":"E1","producer":"ci","producerIdentity":{"type":"workflow","value":"verify"},"subjectRef":"abc","observedAt":"2026-09-25T00:00:00Z",
           "artifactDigest":{"algorithm":"sha256","value":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
           "provenance":{"kind":"ci","issuer":"github","runRef":"run-1"}}
        a={"schemaVersion":1,"subject":{"repository":"x/y","ref":"abc"},"posture":"PASS","evidence":[e],
           "invariantResults":[{"id":"SEC-INV-001","state":"Verified","evidence":["E1"]}],"unknownSecurityEffects":[],"exceptions":[]}
        view=project(a)
        self.assertEqual("run-1",view["invariants"][0]["evidenceProvenance"][0]["provenance"]["runRef"])

if __name__=="__main__": unittest.main()
