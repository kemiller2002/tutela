import unittest
from src.tutela_adversarial_runner import AuthorizationError, Budget, BudgetError, run_campaign

CAMPAIGN={"id":"C1","subject":{"repository":"example/app","ref":"abc123"},"environment":"isolated-test",
 "unknownCoverage":["resource exhaustion not run"],"scenarios":[
 {"id":"S1","category":"state","expectedInvariants":["INV-1"],"attempts":2,"limitations":[]}]}
AUTH={"id":"AUTH-1","authorized":True,"campaignId":"C1","subjectRef":"abc123","environment":"isolated-test","production":False}

class RunnerTests(unittest.TestCase):
 def test_requires_exact_authorization_binding(self):
  bad=dict(AUTH); bad["subjectRef"]="other"
  with self.assertRaises(AuthorizationError): run_campaign(CAMPAIGN,bad,lambda s,a:{"outcome":"RESISTED"})
 def test_rejects_production(self):
  bad=dict(AUTH); bad["production"]=True
  with self.assertRaises(AuthorizationError): run_campaign(CAMPAIGN,bad,lambda s,a:{"outcome":"RESISTED"})
 def test_budget_is_fail_closed(self):
  with self.assertRaises(BudgetError): run_campaign(CAMPAIGN,AUTH,lambda s,a:{"outcome":"RESISTED"},Budget(max_attempts_per_scenario=1))
 def test_deterministic_resisted_result_and_negative_knowledge(self):
  r=run_campaign(CAMPAIGN,AUTH,lambda s,a:{"attempt":a,"outcome":"RESISTED","status":"rejected"},
                 observed_at="2026-09-26T07:00:00Z")
  self.assertEqual("RESISTED",r["results"][0]["outcome"])
  self.assertEqual(2,r["budget"]["attemptsUsed"])
  self.assertEqual(["resource exhaustion not run"],r["unknownCoverage"])
  self.assertEqual(64,len(r["resultDigest"]["value"]))
 def test_adapter_failure_is_indeterminate_without_exception_text(self):
  def fail(s,a): raise RuntimeError("secret detail")
  r=run_campaign(CAMPAIGN,AUTH,fail,observed_at="2026-09-26T07:00:00Z")
  self.assertEqual("INDETERMINATE",r["results"][0]["outcome"])
  self.assertNotIn("secret detail",str(r))

if __name__=="__main__": unittest.main()
