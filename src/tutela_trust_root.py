#!/usr/bin/env python3
"""Fail-closed verification for protected Tutela trust-root changes.

The protected set for a change is the union of the protectedPaths lists in the
base and head policies, so a change cannot remove a path from protection and
modify it without a transition record. Removing a path from protection is
itself a protected change: the record must list the removed path and carry an
approval from an authority allowed to authorize weakening (security-owner).
Approval authorities are taken from the base policy, so a change cannot grant
itself the authority that approves it.
"""
from __future__ import annotations
import argparse, hashlib, json, subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
POLICY_PATH="security/TRUST-ROOT-CHANGE.json"

def run_git(*args):
    return subprocess.check_output(["git",*args],cwd=ROOT,text=True).strip()

def changed_paths(base,head):
    out=run_git("diff","--name-only","--diff-filter=ACDMRTUXB",base,head)
    return [x for x in out.splitlines() if x]

def protected_set(policy):
    return frozenset(policy.get("protectedPaths",[]))

def protected_changes(paths,policy):
    return sorted(set(paths)&protected_set(policy))

def blob(repo_ref,path):
    try: return subprocess.check_output(["git","show",f"{repo_ref}:{path}"],cwd=ROOT,stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError: return None

def load_policy(ref):
    """The trust-root policy at ref; an absent policy protects nothing (its removal is caught as removal of every base path)."""
    data=blob(ref,POLICY_PATH)
    return {} if data is None else json.loads(data)

def transition_digest(ref,paths):
    h=hashlib.sha256()
    for path in sorted(paths):
        data=blob(ref,path)
        h.update(path.encode()); h.update(b"\0")
        if data is None: h.update(b"<absent>")
        else: h.update(data)
        h.update(b"\0")
    return {"algorithm":"sha256","value":h.hexdigest()}

def authorized_roles(policy,weakening):
    return frozenset((role,kind)
        for rule in policy.get("approvalAuthorities",[])
        if "trust-root-change" in rule.get("mayApprove",[]) and (not weakening or rule.get("mayAuthorizeWeakening") is True)
        for role in rule.get("roles",[])
        for kind in rule.get("identityKinds",[]))

def has_authorized_approval(record,policy,weakening):
    allowed=authorized_roles(policy,weakening)
    return any(isinstance(a,dict) and a.get("approved") is True
               and (a.get("role"),(a.get("approverIdentity") or {}).get("kind")) in allowed
               for a in record.get("approvals",[]))

def verify(base,head,record,policy):
    """policy is the head policy; the base policy is read from the base ref."""
    base_policy=load_policy(base)
    removed=sorted(protected_set(base_policy)-protected_set(policy))
    protected=protected_set(base_policy)|protected_set(policy)
    actual=sorted((set(changed_paths(base,head))&protected)|set(removed))
    if not actual: return []
    if not record: return ["protected trust-root files changed without a transition record: "+", ".join(actual)]
    declared=sorted(set(record.get("paths",[])))
    expected_before=transition_digest(base,actual); expected_after=transition_digest(head,actual)
    return [msg for failed,msg in [
        (declared!=actual,"transition paths do not exactly match protected files changed"),
        (record.get("previousDigest")!=expected_before,"transition previousDigest does not match base protected content"),
        (record.get("newDigest")!=expected_after,"transition newDigest does not match head protected content"),
        (not has_authorized_approval(record,base_policy,False),"transition record has no approved approval from an authorized trust-root role"),
        (bool(removed) and not has_authorized_approval(record,base_policy,True),"removing protected paths requires an approved security-owner transition: "+", ".join(removed)),
    ] if failed]

def main():
    p=argparse.ArgumentParser(); p.add_argument("--base",required=True); p.add_argument("--head",default="HEAD"); p.add_argument("--record")
    a=p.parse_args(); record=json.loads(Path(a.record).read_text()) if a.record else None
    errors=verify(a.base,a.head,record,load_policy(a.head))
    print(json.dumps({"base":a.base,"head":a.head,"errors":errors},indent=2))
    return 1 if errors else 0
if __name__=="__main__": raise SystemExit(main())
