import unittest
from src.tutela_concurrency_adapter import ConcurrencyPolicy, ConcurrencyPolicyError, run_concurrent
from src.tutela_dependency_fault_adapter import FaultPolicyError, inject_dependency_fault
from src.tutela_resource_pressure import ResourcePolicy, ResourcePolicyError, run_synthetic_pressure

class Double:
 tutela_test_double=True
 def inject(self,kind,n): return {"outcome":"DEGRADED_SAFE","kind":kind,"attempt":n}
class NotDouble:
 def inject(self,kind,n): return {"outcome":"RESISTED"}

class StressAdapterTests(unittest.TestCase):
 def test_concurrency_budget_and_violation_propagation(self):
  s={"concurrency":{"workers":2,"operations":3}}
  r=run_concurrent(s,lambda s,n:{"outcome":"VIOLATED" if n==2 else "RESISTED"})
  self.assertEqual("VIOLATED",r["outcome"])
  with self.assertRaises(ConcurrencyPolicyError):
   run_concurrent({"concurrency":{"workers":5,"operations":1}},lambda s,n:{},ConcurrencyPolicy(max_workers=4))
 def test_dependency_fault_requires_test_double(self):
  s={"dependencyFault":{"kind":"timeout","count":2}}
  self.assertEqual("DEGRADED_SAFE",inject_dependency_fault(s,Double())["outcome"])
  with self.assertRaises(FaultPolicyError): inject_dependency_fault(s,NotDouble())
 def test_resource_pressure_is_budgeted_and_probe_driven(self):
  s={"resourcePressure":{"units":10,"iterations":3}}
  r=run_synthetic_pressure(s,lambda units,n:{"outcome":"RESISTED","units":units})
  self.assertEqual("RESISTED",r["outcome"])
  with self.assertRaises(ResourcePolicyError):
   run_synthetic_pressure({"resourcePressure":{"units":101,"iterations":1}},lambda u,n:{},ResourcePolicy(max_units=100))

if __name__=="__main__": unittest.main()
