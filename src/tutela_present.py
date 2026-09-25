#!/usr/bin/env python3
"""Project a validated Tutela assessment into presentation-only view models."""
from __future__ import annotations
import json, sys
from pathlib import Path
try:
    from .tutela_gate import derive
except ImportError:
    from tutela_gate import derive

def project(a):
    posture,reasons=derive(a)
    evidence={e.get("id"):e for e in a.get("evidence",[]) if isinstance(e,dict) and e.get("id")}
    invariants=[]
    for x in a.get("invariantResults",[]):
        invariants.append({"id":x.get("id"),"state":x.get("state"),"evidence":x.get("evidence",[]),
          "requiresIndependentVerification":bool(x.get("requiresIndependentVerification")),
          "evidenceProvenance":[{"id":eid,"producer":evidence.get(eid,{}).get("producer"),"observedAt":evidence.get(eid,{}).get("observedAt"),
            "artifactDigest":evidence.get(eid,{}).get("artifactDigest"),"provenance":evidence.get(eid,{}).get("provenance")} for eid in x.get("evidence",[])]})
    return {"schemaVersion":1,"assessmentId":a.get("assessmentId"),"subject":a.get("subject"),"posture":posture,
      "reasons":reasons,"scope":a.get("scope",[]),"invariants":invariants,"unknownSecurityEffects":a.get("unknownSecurityEffects",[]),
      "exceptions":a.get("exceptions",[]),"limitations":a.get("limitations",[]),
      "qualification":"This posture describes the defined scope and evidence. It is not a general claim that the system is secure."}

def main():
    a=json.loads(Path(sys.argv[1]).read_text())
    print(json.dumps(project(a),indent=2))
if __name__=="__main__": main()
