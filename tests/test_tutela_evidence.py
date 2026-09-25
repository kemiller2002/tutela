import tempfile, unittest
from argparse import Namespace
from pathlib import Path
from src.tutela_evidence import build

class EvidenceGeneratorTests(unittest.TestCase):
    def test_digest_is_deterministic_and_bound_to_subject(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"artifact.txt"; f.write_bytes(b"tutela\n")
            base=dict(artifact=str(f),id="SEC-EVD-100",type="Test",source="fixture",subject_ref="abc123",producer="CI",
              producer_identity_type="workflow",producer_identity_value="tutela-foundation",provenance_kind="ci",
              provenance_issuer="github-actions",run_ref="run-1",workflow_ref="wf@sha",observed_at="2026-09-25T00:00:00Z",algorithm="sha256")
            one=build(Namespace(**base)); two=build(Namespace(**base))
            self.assertEqual(one["artifactDigest"],two["artifactDigest"])
            self.assertEqual("abc123",one["subjectRef"])
            self.assertEqual(64,len(one["artifactDigest"]["value"]))
            self.assertEqual("run-1",one["provenance"]["runRef"])
if __name__=="__main__": unittest.main()
