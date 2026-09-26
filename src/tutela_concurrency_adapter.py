"""Bounded concurrent/replay executor for authorized test adapters."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

class ConcurrencyPolicyError(RuntimeError): pass
@dataclass(frozen=True)
class ConcurrencyPolicy:
    max_workers:int=4
    max_operations:int=12

def run_concurrent(scenario, operation, policy=ConcurrencyPolicy()):
    cfg=scenario.get("concurrency",{})
    workers=int(cfg.get("workers",1)); operations=int(cfg.get("operations",1))
    if workers<1 or workers>policy.max_workers: raise ConcurrencyPolicyError("worker budget exceeded")
    if operations<1 or operations>policy.max_operations: raise ConcurrencyPolicyError("operation budget exceeded")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results=list(pool.map(lambda i: operation(scenario,i+1),range(operations)))
    outcomes=[r.get("outcome") for r in results]
    if "VIOLATED" in outcomes: outcome="VIOLATED"
    elif outcomes and all(x=="RESISTED" for x in outcomes): outcome="RESISTED"
    elif outcomes and all(x in {"RESISTED","DEGRADED_SAFE"} for x in outcomes): outcome="DEGRADED_SAFE"
    else: outcome="INDETERMINATE"
    return {"outcome":outcome,"workers":workers,"operations":operations,"observations":results}
