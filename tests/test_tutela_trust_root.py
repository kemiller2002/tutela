import unittest
from unittest.mock import patch
from src.tutela_trust_root import protected_changes, verify

POLICY={"protectedPaths":["security/P.json","src/gate.py"]}

class TrustRootDiffTests(unittest.TestCase):
    def test_unprotected_change_needs_no_record(self):
        with patch("src.tutela_trust_root.changed_paths",return_value=["README.md"]):
            self.assertEqual([],verify("base","head",None,POLICY))

    def test_protected_change_without_record_fails(self):
        with patch("src.tutela_trust_root.changed_paths",return_value=["src/gate.py"]):
            self.assertIn("without a transition record",verify("base","head",None,POLICY)[0])

    def test_record_must_cover_exact_protected_diff(self):
        record={"paths":["src/gate.py","security/P.json"],"previousDigest":{},"newDigest":{}}
        with patch("src.tutela_trust_root.changed_paths",return_value=["src/gate.py"]):
            self.assertIn("exactly match",verify("base","head",record,POLICY)[0])

    def test_digests_are_bound_to_actual_base_and_head(self):
        record={"paths":["src/gate.py"],"previousDigest":{"algorithm":"sha256","value":"wrong"},"newDigest":{"algorithm":"sha256","value":"wrong"}}
        with patch("src.tutela_trust_root.changed_paths",return_value=["src/gate.py"]), patch("src.tutela_trust_root.transition_digest",side_effect=[{"algorithm":"sha256","value":"before"},{"algorithm":"sha256","value":"after"}]):
            errors=verify("base","head",record,POLICY)
        self.assertEqual(2,len(errors))

    def test_matching_transition_passes(self):
        record={"paths":["src/gate.py"],"previousDigest":{"algorithm":"sha256","value":"before"},"newDigest":{"algorithm":"sha256","value":"after"}}
        with patch("src.tutela_trust_root.changed_paths",return_value=["src/gate.py"]), patch("src.tutela_trust_root.transition_digest",side_effect=[record["previousDigest"],record["newDigest"]]):
            self.assertEqual([],verify("base","head",record,POLICY))

if __name__=="__main__": unittest.main()
