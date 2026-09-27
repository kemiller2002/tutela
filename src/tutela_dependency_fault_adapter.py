"""Dependency fault adapter using injected test doubles only."""
from dataclasses import dataclass

class FaultPolicyError(RuntimeError): pass
ALLOWED={"timeout","unavailable","malformed-response","stale-response","duplicate-response"}
@dataclass(frozen=True)
class FaultPolicy:
    max_injections:int=5

def inject_dependency_fault(scenario, dependency_double, policy=FaultPolicy()):
    cfg=scenario.get("dependencyFault",{})
    kind=cfg.get("kind"); count=int(cfg.get("count",1))
    if kind not in ALLOWED: raise FaultPolicyError("unsupported dependency fault")
    if count<1 or count>policy.max_injections: raise FaultPolicyError("fault injection budget exceeded")
    if getattr(dependency_double,"tutela_test_double",False) is not True:
        raise FaultPolicyError("fault injection requires an explicit Tutela test double")
    observations=[]
    for i in range(count):
        observations.append(dependency_double.inject(kind,i+1))
    outcomes=[x.get("outcome") for x in observations]
    outcome="VIOLATED" if "VIOLATED" in outcomes else ("DEGRADED_SAFE" if outcomes and all(x in {"RESISTED","DEGRADED_SAFE"} for x in outcomes) else "INDETERMINATE")
    return {"outcome":outcome,"fault":kind,"injections":count,"observations":observations}
