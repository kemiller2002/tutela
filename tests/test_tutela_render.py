import unittest
from src.tutela_render import render
class RenderTests(unittest.TestCase):
    def test_renderer_uses_derived_posture_and_both_component_vocabularies(self):
        a={"schemaVersion":1,"assessmentId":"A1","subject":{"repository":"x/y","ref":"abc"},"posture":"PASS","invariantResults":[{"id":"SEC-INV-001","state":"Unknown","evidence":[]}],"unknownSecurityEffects":[],"exceptions":[]}
        out=render(a)
        self.assertIn('data-posture="indeterminate"',out)
        self.assertIn("<ef-security-posture",out)
        self.assertIn("<ef-print-security-record",out)
        self.assertNotIn('data-posture="pass"',out)
if __name__=="__main__": unittest.main()
