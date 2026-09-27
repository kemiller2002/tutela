import unittest
from src.tutela_orchestrator import OrchestrationError, evidence_record, execute_campaign

AUTH={"id":"AUTH-1","authorized":True,"campaignId":"C1","subjectRef":"abc","environment":"test","production":False,"allowedOrigins":[]}
BASE={"id":"C1","subject":{"repository":"x/y","ref":"abc"},"environment":"test","unknownCoverage":[],"limitations":[]}

class Double:
 tutela_test_double=True
 def inject(self,k,n): return {"outcome":"DEGRADED_SAFE","kind":k}
class OrchestratorTests(unittest.TestCase):
 def test_fault_campaign_emits_digest_and_evidence(self):
  c={**BASE,"scenarios":[{"id":"S1","category":"dependency","expectedInvariants":["I1"],"limitations":[],
       "dependencyFault":{"kind":"timeout","count":1}}]}
  b=execute_campaign(c,AUTH,dependency_doubles={"S1":Double()},observed_at="2026-09-26T08:00:00Z")
  self.assertEqual("DEGRADED_SAFE",b["results"][0]["outcome"]); self.assertEqual(64,len(b["bundleDigest"]["value"]))
  e=evidence_record(b); self.assertEqual("AdversarialTest",e["type"]); self.assertEqual("abc",e["subjectRef"])
 def test_missing_runtime_binding_is_negative_knowledge(self):
  c={**BASE,"scenarios":[{"id":"S1","category":"resource","expectedInvariants":["I1"],"limitations":[],
       "resourcePressure":{"units":2,"iterations":1}}]}
  b=execute_campaign(c,AUTH,observed_at="2026-09-26T08:00:00Z")
  self.assertEqual("INDETERMINATE",b["results"][0]["outcome"])
  self.assertIn("S1: execution indeterminate",b["unknownCoverage"])
 def test_ambiguous_capability_is_indeterminate(self):
  c={**BASE,"scenarios":[{"id":"S1","category":"custom","expectedInvariants":["I1"],"limitations":[],
       "http":{"url":"http://127.0.0.1/"}, "resourcePressure":{"units":1,"iterations":1}}]}
  b=execute_campaign(c,AUTH,observed_at="2026-09-26T08:00:00Z")
  self.assertEqual("INDETERMINATE",b["results"][0]["outcome"])

if __name__=="__main__": unittest.main()
