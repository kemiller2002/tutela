#!/usr/bin/env python3
"""Fail-closed verification for protected Tutela trust-root changes.

The protected set for a change is the union of the protectedPaths lists in the
base and head policies, so a change cannot remove a path from protection and
modify it without a transition record. Removing a path from protection is
itself a protected change: the record must list the removed path and carry an
approval from an authority allowed to authorize weakening (security-owner).
Approval authorities are taken from the base policy, so a change cannot grant
itself the authority that approves it.

Every transition record the change adds is checked on its own (exact paths
within the protected change, base/head digests over its own paths, an
authorized approval, security-owner approval for any removal it covers), and
the union of their paths must cover every protected change. A transition
record that already exists at the base is merged history: modifying,
renaming or deleting it is rejected.
"""
from __future__ import annotations
import argparse, hashlib, json, subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
POLICY_PATH="security/TRUST-ROOT-CHANGE.json"
TRANSITION_DIRECTORY="security/transitions"

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

def record_directories(*policies):
    """The transition directories of the base and head policies, always including the default."""
    return sorted({TRANSITION_DIRECTORY}|{d.rstrip("/") for p in policies
        for d in [(p.get("transitionRecord") or {}).get("directory")] if isinstance(d,str) and d.strip("/")})

def load_record(ref,path):
    data=blob(ref,path)
    if data is None: return None
    try: return json.loads(data)
    except ValueError: return None

def transition_records(base,head,directories):
    """(path, state, record) for every transition record the change adds, modifies or deletes.

    state is "added" when the path is absent at the base; anything else touches merged history.
    Renames are reported as a deletion and an addition, so a moved record is a deleted one.
    """
    out=run_git("diff","--name-only","--no-renames",base,head,"--",*directories)
    paths=sorted(x for x in out.splitlines() if x.endswith(".json"))
    return [(path,"added" if blob(base,path) is None else "modified" if blob(head,path) is not None else "deleted",load_record(head,path))
            for path in paths]

def check_record(path,record,actual,removed,base,head,base_policy):
    """Errors for one added transition record, each prefixed with the record's path."""
    if not isinstance(record,dict): return [f"{path}: transition record is not a JSON object"]
    paths=record.get("paths")
    if not isinstance(paths,list) or not paths or not all(isinstance(x,str) for x in paths):
        return [f"{path}: transition record lists no paths"]
    declared=sorted(set(paths)); covered_removals=sorted(set(declared)&set(removed))
    return [f"{path}: {msg}" for failed,msg in [
        (not set(declared)<=set(actual),"transition paths do not exactly match protected files changed: not changed or not protected: "+", ".join(sorted(set(declared)-set(actual)))),
        (record.get("previousDigest")!=transition_digest(base,declared),"transition previousDigest does not match base protected content"),
        (record.get("newDigest")!=transition_digest(head,declared),"transition newDigest does not match head protected content"),
        (not has_authorized_approval(record,base_policy,False),"transition record has no approved approval from an authorized trust-root role"),
        (bool(covered_removals) and not has_authorized_approval(record,base_policy,True),"removing protected paths requires an approved security-owner transition: "+", ".join(covered_removals)),
    ] if failed]

def verify(base,head,policy):
    """policy is the head policy; the base policy is read from the base ref."""
    base_policy=load_policy(base)
    removed=sorted(protected_set(base_policy)-protected_set(policy))
    protected=protected_set(base_policy)|protected_set(policy)
    actual=sorted((set(changed_paths(base,head))&protected)|set(removed))
    entries=transition_records(base,head,record_directories(base_policy,policy))
    history=[f"{path}: transition record already exists at base and must not be changed ({state})" for path,state,_ in entries if state!="added"]
    added=[(path,record) for path,state,record in entries if state=="added"]
    if not added:
        return history+(["protected trust-root files changed without a transition record: "+", ".join(actual)] if actual else [])
    per_record=[e for path,record in added for e in check_record(path,record,actual,removed,base,head,base_policy)]
    covered=set().union(*[set(r["paths"]) for _,r in added if isinstance(r,dict) and isinstance(r.get("paths"),list) and all(isinstance(x,str) for x in r["paths"])])
    uncovered=sorted(set(actual)-covered)
    return history+per_record+(["transition paths do not exactly match protected files changed: not covered by any transition record: "+", ".join(uncovered)] if uncovered else [])

def main():
    p=argparse.ArgumentParser(description="Every transition record in the change is discovered from the base..head diff.")
    p.add_argument("--base",required=True); p.add_argument("--head",default="HEAD")
    a=p.parse_args()
    errors=verify(a.base,a.head,load_policy(a.head))
    print(json.dumps({"base":a.base,"head":a.head,"errors":errors},indent=2))
    return 1 if errors else 0
if __name__=="__main__": raise SystemExit(main())
