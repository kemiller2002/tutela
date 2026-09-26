#!/usr/bin/env python3
"""Emit Tutela identity-binding evidence from authoritative GitHub user data."""
from __future__ import annotations
import argparse, json
from datetime import datetime, timezone

def binding_from_github(user, observed_at, source_ref):
    uid=user.get("id"); login=user.get("login")
    if not isinstance(uid,int) or uid <= 0: raise ValueError("GitHub numeric account id is required")
    if not login: raise ValueError("GitHub login is required")
    return {
      "schemaVersion":1,
      "type":"IdentityBinding",
      "provider":"github",
      "subjectId":str(uid),
      "login":login,
      "bindingVerified":True,
      "bindingEvidence":[{
        "kind":"platform-api-observation",
        "issuer":"github",
        "sourceRef":source_ref,
        "observedAt":observed_at
      }]
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--github-user-json",required=True,help="JSON response from GitHub GET /users/{login}")
    p.add_argument("--source-ref",required=True)
    p.add_argument("--observed-at")
    args=p.parse_args()
    user=json.loads(args.github_user_json)
    observed=args.observed_at or datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
    print(json.dumps(binding_from_github(user,observed,args.source_ref),indent=2,sort_keys=True))
if __name__=="__main__": main()
