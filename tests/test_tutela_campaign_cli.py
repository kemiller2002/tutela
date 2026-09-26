import json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from src import tutela_campaign

BUNDLE={"results":[{"outcome":"RESISTED"}],"unknownCoverage":[]}
class CampaignCliTests(unittest.TestCase):
 def files(self):
  d=tempfile.TemporaryDirectory(); root=Path(d.name)
  (root/"c.json").write_text(json.dumps({"id":"C"})); (root/"a.json").write_text(json.dumps({"id":"A"}))
  return d,root
 def test_writes_bundle_and_evidence_and_returns_zero(self):
  d,r=self.files()
  with d, patch("src.tutela_campaign.execute_campaign",return_value={**BUNDLE,"campaignId":"C","subject":{"ref":"x"},"observedAt":"2026-01-01T00:00:00Z","bundleDigest":{"algorithm":"sha256","value":"a"*64},"limitations":[],"authorizationRef":"A"}):
   code=tutela_campaign.main([str(r/"c.json"),str(r/"a.json"),"--bundle-out",str(r/"b.json"),"--evidence-out",str(r/"e.json")])
   self.assertEqual(0,code); self.assertTrue((r/"b.json").exists()); self.assertTrue((r/"e.json").exists())
 def test_exit_codes_distinguish_violation_and_unknown(self):
  self.assertEqual(2,tutela_campaign.exit_for({"results":[{"outcome":"VIOLATED"}],"unknownCoverage":[]}))
  self.assertEqual(3,tutela_campaign.exit_for({"results":[{"outcome":"INDETERMINATE"}],"unknownCoverage":[]}))
  self.assertEqual(3,tutela_campaign.exit_for({"results":[{"outcome":"RESISTED"}],"unknownCoverage":["not covered"]}))
 def test_input_failure_is_redacted(self):
  d,r=self.files()
  with d, patch("src.tutela_campaign.execute_campaign",side_effect=RuntimeError("secret-token")):
   self.assertEqual(4,tutela_campaign.main([str(r/"c.json"),str(r/"a.json")]))

if __name__=="__main__": unittest.main()
