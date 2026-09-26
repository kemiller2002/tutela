import unittest
from src.tutela_present import project

class AdversarialPresentationTests(unittest.TestCase):
 def test_projects_counts_blockers_unknowns_and_recovery(self):
  a={"schemaVersion":1,"subject":{"repository":"x/y","ref":"abc"},"posture":"BLOCKED",
    "invariantResults":[],"unknownSecurityEffects":[],"exceptions":[],
    "adversarialResults":[
      {"id":"A1","campaignId":"C1","outcome":"VIOLATED","required":True,"expectedInvariants":["I1"],"evidence":["E1"],"recovery":"rollback","limitations":[]},
      {"id":"A2","campaignId":"C1","outcome":"NOT_RUN","required":True,"expectedInvariants":["I2"],"evidence":[],"limitations":["fixture missing"]},
      {"id":"A3","campaignId":"C1","outcome":"DEGRADED_SAFE","required":True,"expectedInvariants":["I3"],"evidence":["E3"],"recovery":"automatic","limitations":[]}]}
  v=project(a)
  self.assertEqual("BLOCKED",v["posture"])
  self.assertEqual(1,v["adversarial"]["summary"]["VIOLATED"])
  self.assertEqual(["A1"],v["adversarial"]["requiredBlockers"])
  self.assertEqual(["A2"],v["adversarial"]["requiredUnknowns"])
  self.assertEqual("automatic",v["adversarial"]["results"][2]["recovery"])

if __name__=="__main__": unittest.main()
