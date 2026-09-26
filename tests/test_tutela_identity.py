import unittest
from src.tutela_identity import binding_from_github

class IdentityTests(unittest.TestCase):
    def test_uses_immutable_numeric_github_id(self):
        x=binding_from_github({"id":12345,"login":"alice"},"2026-09-26T00:00:00Z","github-api:/users/alice")
        self.assertEqual("12345",x["subjectId"]); self.assertEqual("alice",x["login"]); self.assertTrue(x["bindingVerified"])
    def test_login_change_preserves_authoritative_subject(self):
        a=binding_from_github({"id":12345,"login":"alice"},"2026-09-25T00:00:00Z","old")
        b=binding_from_github({"id":12345,"login":"alice-new"},"2026-09-26T00:00:00Z","new")
        self.assertEqual(a["subjectId"],b["subjectId"]); self.assertNotEqual(a["login"],b["login"])
    def test_missing_numeric_id_rejected(self):
        with self.assertRaises(ValueError): binding_from_github({"login":"alice"},"2026-09-26T00:00:00Z","x")
    def test_string_or_forged_shape_id_rejected(self):
        with self.assertRaises(ValueError): binding_from_github({"id":"12345","login":"alice"},"2026-09-26T00:00:00Z","x")
    def test_missing_login_rejected(self):
        with self.assertRaises(ValueError): binding_from_github({"id":12345},"2026-09-26T00:00:00Z","x")
if __name__=="__main__": unittest.main()
