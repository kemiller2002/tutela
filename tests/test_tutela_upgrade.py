import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from src.tutela_install import install,TUTELA_VERSION
from src.tutela_upgrade import UpgradeError,inspect,upgrade

class UpgradeTests(unittest.TestCase):
 def test_install_records_version_and_ownership(self):
  with tempfile.TemporaryDirectory() as d:
   install(d,"owner/repo","abc")
   m=json.loads((Path(d)/".tutela/install.json").read_text())
   self.assertEqual(TUTELA_VERSION,m["tutelaVersion"])
   self.assertIn(".tutela/security-assessment.json",m["ownership"]["repository"])
 def test_upgrade_preserves_repository_state(self):
  with tempfile.TemporaryDirectory() as d:
   install(d,"owner/repo","abc"); p=Path(d)/".tutela/security-assessment.json"; p.write_text('{"custom":true}')
   mpath=Path(d)/".tutela/install.json"; m=json.loads(mpath.read_text()); m["tutelaVersion"]="0.1.0"; mpath.write_text(json.dumps(m))
   r=upgrade(d)
   self.assertEqual("UPGRADED",r["status"]); self.assertEqual('{"custom":true}',p.read_text())
   self.assertEqual(TUTELA_VERSION,json.loads(mpath.read_text())["tutelaVersion"])
 def test_unmanaged_upgrade_refused(self):
  with tempfile.TemporaryDirectory() as d:
   self.assertEqual("UNMANAGED",inspect(d)["status"])
   with self.assertRaises(UpgradeError): upgrade(d)
 def test_incompatible_manifest_refused(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/".tutela/install.json"; p.parent.mkdir(parents=True); p.write_text('{"schemaVersion":999,"tutelaVersion":"old"}')
   self.assertEqual("INCOMPATIBLE",inspect(d)["status"])
   with self.assertRaises(UpgradeError): upgrade(d)
 def test_inspection_is_non_mutating(self):
  with tempfile.TemporaryDirectory() as d:
   install(d,"owner/repo","abc"); p=Path(d)/".tutela/security-assessment.json"; before=p.read_text()
   inspect(d); self.assertEqual(before,p.read_text())

if __name__=="__main__": unittest.main()
