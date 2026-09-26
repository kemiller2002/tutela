#!/usr/bin/env python3
"""Bounded, authorization-gated adversarial campaign runner.

The runner is transport-agnostic: adapters perform observations. The core owns
authorization, budgets, deterministic ordering, evidence shaping, and fail-closed
handling of anything it cannot establish.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib, json
from pathlib import Path
from typing import Callable

@dataclass(frozen=True)
class Budget:
    max_scenarios: int = 25
    max_attempts_per_scenario: int = 3
    max_total_attempts: int = 50

class AuthorizationError(RuntimeError): pass
class BudgetError(RuntimeError): pass

def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

def load_json(path):
    return json.loads(Path(path).read_text())

def verify_authorization(campaign: dict, authorization: dict) -> None:
    if authorization.get("authorized") is not True:
        raise AuthorizationError("campaign execution requires explicit authorization")
    if authorization.get("campaignId") != campaign.get("id"):
        raise AuthorizationError("authorization campaignId does not match campaign")
    subject=campaign.get("subject",{})
    if authorization.get("subjectRef") != subject.get("ref"):
        raise AuthorizationError("authorization subjectRef does not match immutable subject")
    if authorization.get("environment") != campaign.get("environment"):
        raise AuthorizationError("authorization environment does not match campaign")
    if authorization.get("production") is True:
        raise AuthorizationError("production execution is not supported by this harness")

def run_campaign(campaign: dict, authorization: dict, adapter: Callable[[dict,int],dict],
                 budget: Budget=Budget(), observed_at: str|None=None) -> dict:
    verify_authorization(campaign, authorization)
    scenarios=campaign.get("scenarios",[])
    if len(scenarios)>budget.max_scenarios:
        raise BudgetError("scenario count exceeds authorized runner budget")
    total_attempts=0
    results=[]
    for scenario in scenarios:
        requested=int(scenario.get("attempts",1))
        if requested<1 or requested>budget.max_attempts_per_scenario:
            raise BudgetError(f"{scenario.get('id')}: attempts exceed per-scenario budget")
        if total_attempts+requested>budget.max_total_attempts:
            raise BudgetError("campaign exceeds total attempt budget")
        observations=[]
        outcome="INDETERMINATE"
        for attempt in range(1,requested+1):
            total_attempts+=1
            try:
                obs=adapter(scenario,attempt)
                observations.append(obs)
            except Exception as exc:
                observations.append({"attempt":attempt,"status":"adapter-error","detail":type(exc).__name__})
                outcome="INDETERMINATE"
                break
        else:
            reported=[o.get("outcome") for o in observations]
            if reported and all(x=="RESISTED" for x in reported): outcome="RESISTED"
            elif reported and all(x in {"RESISTED","DEGRADED_SAFE"} for x in reported): outcome="DEGRADED_SAFE"
            elif "VIOLATED" in reported: outcome="VIOLATED"
            else: outcome="INDETERMINATE"
        results.append({
            "id":scenario.get("id"),"category":scenario.get("category"),
            "expectedInvariants":scenario.get("expectedInvariants",[]),
            "outcome":outcome,"attempts":observations,
            "limitations":scenario.get("limitations",[])
        })
    at=observed_at or _now()
    result={"schemaVersion":1,"campaignId":campaign["id"],"subject":campaign["subject"],
            "environment":campaign["environment"],"observedAt":at,
            "authorizationRef":authorization.get("id"),"results":results,
            "unknownCoverage":campaign.get("unknownCoverage",[]),
            "budget":{"maxScenarios":budget.max_scenarios,
                      "maxAttemptsPerScenario":budget.max_attempts_per_scenario,
                      "maxTotalAttempts":budget.max_total_attempts,
                      "attemptsUsed":total_attempts}}
    canonical=json.dumps(result,sort_keys=True,separators=(",",":")).encode()
    result["resultDigest"]={"algorithm":"sha256","value":hashlib.sha256(canonical).hexdigest()}
    return result
