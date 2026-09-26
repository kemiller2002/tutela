import json,tempfile,unittest
from pathlib import Path
from src.tutela_install import install

class InstallTests(unittest.TestCase):
 def test_bootstrap_is_fail_closed_and_installs_gate(self):
  with tempfile.TemporaryDirectory() as d:
   r=install(d,"owner/repo","abc")
   self.assertIn(".tutela/security-assessment.json",r["written"])
   a=json.loads((Path(d)/".tutela/security-assessment.json").read_text())
   self.assertEqual("INDETERMINATE",a["posture"]); self.assertEqual("Unknown",a["invariantResults"][0]["state"])
   self.assertTrue((Path(d)/".tutela/runtime/tutela_gate.py").exists())
 def test_existing_configuration_is_preserved(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/".tutela/security-assessment.json"; p.parent.mkdir(parents=True); p.write_text("keep-me")
   r=install(d,"owner/repo","abc")
   self.assertEqual("keep-me",p.read_text()); self.assertIn(".tutela/security-assessment.json",r["preserved"])
 def test_force_is_explicit(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/".tutela/security-assessment.json"; p.parent.mkdir(parents=True); p.write_text("old")
   install(d,"owner/repo","abc",force=True)
   self.assertNotEqual("old",p.read_text())
 def test_workflow_runs_repository_local_gate(self):
  with tempfile.TemporaryDirectory() as d:
   install(d,"owner/repo","abc")
   w=(Path(d)/".github/workflows/tutela-security.yml").read_text()
   self.assertIn(".tutela/runtime/tutela_gate.py",w); self.assertIn("--check-declared",w)

if __name__=="__main__": unittest.main()
