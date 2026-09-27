#!/usr/bin/env python3
"""Tutela adversarial campaign orchestrator."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib, json
from src.tutela_adversarial_runner import verify_authorization
from src.tutela_http_adapter import HttpPolicy, make_http_adapter
from src.tutela_concurrency_adapter import run_concurrent
from src.tutela_dependency_fault_adapter import inject_dependency_fault
from src.tutela_resource_pressure import run_synthetic_pressure

class OrchestrationError(RuntimeError): pass

def _now(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def _kind(s):
    kinds=[k for k in ("http","concurrency","dependencyFault","resourcePressure") if k in s]
    if len(kinds)!=1: raise OrchestrationError("scenario must declare exactly one execution capability")
    return kinds[0]
def _safe_call(fn):
    try: return fn()
    except Exception as exc:
        return {"outcome":"INDETERMINATE","errorType":type(exc).__name__}

def execute_campaign(campaign, authorization, dependency_doubles=None, pressure_probes=None, observed_at=None):
    verify_authorization(campaign,authorization)
    dependency_doubles=dependency_doubles or {}; pressure_probes=pressure_probes or {}
    http=make_http_adapter(HttpPolicy(tuple(authorization.get("allowedOrigins",[]))))
    results=[]; unknowns=list(campaign.get("unknownCoverage",[]))
    for scenario in campaign.get("scenarios",[]):
        sid=scenario.get("id","unknown")
        try: kind=_kind(scenario)
        except OrchestrationError as exc:
            result={"outcome":"INDETERMINATE","errorType":type(exc).__name__}; kind="invalid"
        else:
            if kind=="http": result=_safe_call(lambda:http(scenario,1))
            elif kind=="concurrency":
                # Concurrency composes over a declarative nested HTTP operation only.
                op=scenario.get("operation",{})
                nested=dict(scenario); nested.pop("concurrency",None); nested["http"]=op.get("http")
                nested["expect"]=op.get("expect",{})
                result=_safe_call(lambda:run_concurrent(scenario,lambda _s,n:http(nested,n)))
            elif kind=="dependencyFault":
                result=_safe_call(lambda:inject_dependency_fault(scenario,dependency_doubles[sid]))
            else:
                result=_safe_call(lambda:run_synthetic_pressure(scenario,pressure_probes[sid]))
        if result.get("outcome")=="INDETERMINATE":
            unknowns.append(f"{sid}: execution indeterminate")
        results.append({"id":sid,"category":scenario.get("category"),"capability":kind,
                        "expectedInvariants":scenario.get("expectedInvariants",[]),
                        "outcome":result.get("outcome","INDETERMINATE"),"observation":result,
                        "limitations":scenario.get("limitations",[])})
    at=observed_at or _now()
    bundle={"schemaVersion":1,"campaignId":campaign["id"],"subject":campaign["subject"],
            "environment":campaign["environment"],"authorizationRef":authorization["id"],
            "observedAt":at,"results":results,"unknownCoverage":unknowns,
            "limitations":campaign.get("limitations",[])}
    canonical=json.dumps(bundle,sort_keys=True,separators=(",",":")).encode()
    bundle["bundleDigest"]={"algorithm":"sha256","value":hashlib.sha256(canonical).hexdigest()}
    return bundle

def evidence_record(bundle, producer="Tutela adversarial orchestrator"):
    return {"id":f"ADV-{bundle['campaignId']}","type":"AdversarialTest",
      "source":f"campaign:{bundle['campaignId']}","subjectRef":bundle["subject"]["ref"],
      "observedAt":bundle["observedAt"],"producer":producer,
      "producerIdentity":{"type":"tool","value":"tutela-adversarial-orchestrator"},
      "artifactDigest":bundle["bundleDigest"],
      "provenance":{"kind":"adversarial-campaign","issuer":"tutela","runRef":bundle["authorizationRef"]},
      "method":"bounded authorized adversarial campaign","redacted":True,
      "result":json.dumps({r["id"]:r["outcome"] for r in bundle["results"]},sort_keys=True),
      "limitations":bundle["limitations"]+bundle["unknownCoverage"],
      "bundleDigest":bundle["bundleDigest"]}
