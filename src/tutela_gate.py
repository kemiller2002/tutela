#!/usr/bin/env python3
"""Tutela semantic validator and deterministic release-posture gate.

No third-party dependencies. This engine does not discover vulnerabilities.
It derives posture from explicit assessment state and fails closed on malformed
or contradictory security state.
"""
from __future__ import annotations
import argparse, json, sys
from datetime import datetime, timezone
from pathlib import Path

POSTURES={"PASS","CONDITIONAL","BLOCKED","INDETERMINATE"}
INV_STATES={"Verified","Violated","Unknown","Stale","NotApplicable"}

def now_utc(): return datetime.now(timezone.utc)

def parse_time(value):
    if not value: return None
    return datetime.fromisoformat(value.replace("Z","+00:00"))

def validate(a):
    errors=[]
    if a.get("schemaVersion") != 1: errors.append("schemaVersion must be 1")
    subject=a.get("subject") or {}
    if not subject.get("repository"): errors.append("subject.repository is required")
    if not subject.get("ref"): errors.append("subject.ref is required")
    inv=a.get("invariantResults")
    if not isinstance(inv,list): errors.append("invariantResults must be an array")
    else:
        ids=set()
        for i,x in enumerate(inv):
            p=f"invariantResults[{i}]"
            if not isinstance(x,dict): errors.append(f"{p} must be an object"); continue
            iid=x.get("id")
            if not iid: errors.append(f"{p}.id is required")
            elif iid in ids: errors.append(f"duplicate invariant id {iid}")
            else: ids.add(iid)
            if x.get("state") not in INV_STATES: errors.append(f"{p}.state is invalid")
            if x.get("state")=="Verified" and not x.get("evidence"):
                errors.append(f"{iid or p} cannot be Verified without evidence")
            if x.get("state")=="Verified" and x.get("contradictoryEvidence"):
                errors.append(f"{iid or p} cannot be Verified with contradictory evidence")
    exceptions=a.get("exceptions",[])
    if not isinstance(exceptions,list): errors.append("exceptions must be an array")
    else:
        for i,e in enumerate(exceptions):
            if not isinstance(e,dict): errors.append(f"exceptions[{i}] must be an object"); continue
            for k in ("id","approver","expiresAt"):
                if not e.get(k): errors.append(f"exceptions[{i}].{k} is required")
    return errors

def valid_exceptions(a, at=None):
    at=at or now_utc()
    out=[]
    for e in a.get("exceptions",[]):
        try:
            if e.get("approved") is True and parse_time(e.get("expiresAt")) and parse_time(e["expiresAt"])>at:
                out.append(e)
        except ValueError:
            pass
    return out

def derive(a, at=None):
    errors=validate(a)
    if errors: return "INDETERMINATE", ["invalid assessment: "+x for x in errors]
    inv=a["invariantResults"]
    unknown_effects=a.get("unknownSecurityEffects",[])
    violated=[x["id"] for x in inv if x["state"]=="Violated"]
    unknown=[x["id"] for x in inv if x["state"]=="Unknown"]
    stale=[x["id"] for x in inv if x["state"]=="Stale"]
    missing=[x["id"] for x in inv if x["state"]=="Verified" and not x.get("evidence")]
    exceptions=valid_exceptions(a,at)
    accepted=set()
    for e in exceptions: accepted.update(e.get("covers",[]))
    hard=[x for x in violated+unknown_effects if x not in accepted]
    if hard: return "BLOCKED", hard
    indeterminate=[x for x in unknown+stale+missing if x not in accepted]
    if indeterminate: return "INDETERMINATE", indeterminate
    if exceptions: return "CONDITIONAL", [e["id"] for e in exceptions]
    return "PASS", []

def main():
    p=argparse.ArgumentParser()
    p.add_argument("assessment")
    p.add_argument("--check-declared",action="store_true")
    args=p.parse_args()
    a=json.loads(Path(args.assessment).read_text())
    posture,reasons=derive(a)
    print(json.dumps({"derivedPosture":posture,"reasons":reasons},indent=2))
    if args.check_declared and a.get("posture") != posture:
        print(f"declared posture {a.get('posture')} != derived posture {posture}",file=sys.stderr)
        return 2
    return 1 if posture in {"BLOCKED","INDETERMINATE"} else 0

if __name__=="__main__": raise SystemExit(main())
