"""Synthetic local resource-pressure evaluator. Does not generate network load."""
from dataclasses import dataclass

class ResourcePolicyError(RuntimeError): pass
@dataclass(frozen=True)
class ResourcePolicy:
    max_units:int=10000
    max_iterations:int=100

def run_synthetic_pressure(scenario, probe, policy=ResourcePolicy()):
    cfg=scenario.get("resourcePressure",{})
    units=int(cfg.get("units",1)); iterations=int(cfg.get("iterations",1))
    if units<1 or units>policy.max_units: raise ResourcePolicyError("resource unit budget exceeded")
    if iterations<1 or iterations>policy.max_iterations: raise ResourcePolicyError("iteration budget exceeded")
    observations=[probe(units,i+1) for i in range(iterations)]
    outcomes=[x.get("outcome") for x in observations]
    if "VIOLATED" in outcomes: outcome="VIOLATED"
    elif outcomes and all(x=="RESISTED" for x in outcomes): outcome="RESISTED"
    elif outcomes and all(x in {"RESISTED","DEGRADED_SAFE"} for x in outcomes): outcome="DEGRADED_SAFE"
    else: outcome="INDETERMINATE"
    return {"outcome":outcome,"units":units,"iterations":iterations,"observations":observations}
