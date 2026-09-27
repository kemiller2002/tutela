#!/usr/bin/env python3
"""Fail-closed verification for protected Tutela trust-root changes."""
from __future__ import annotations
import argparse, hashlib, json, subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
POLICY=ROOT/"security"/"TRUST-ROOT-CHANGE.json"

def run_git(*args):
    return subprocess.check_output(["git",*args],cwd=ROOT,text=True).strip()

def changed_paths(base,head):
    out=run_git("diff","--name-only","--diff-filter=ACDMRTUXB",base,head)
    return [x for x in out.splitlines() if x]

def protected_changes(paths,policy):
    protected=set(policy.get("protectedPaths",[]))
    return sorted(set(paths)&protected)

def blob(repo_ref,path):
    try: return subprocess.check_output(["git","show",f"{repo_ref}:{path}"],cwd=ROOT)
    except subprocess.CalledProcessError: return None

def transition_digest(ref,paths):
    h=hashlib.sha256()
    for path in sorted(paths):
        data=blob(ref,path)
        h.update(path.encode()); h.update(b"\0")
        if data is None: h.update(b"<absent>")
        else: h.update(data)
        h.update(b"\0")
    return {"algorithm":"sha256","value":h.hexdigest()}

def verify(base,head,record,policy):
    errors=[]; actual=protected_changes(changed_paths(base,head),policy)
    if not actual: return errors
    if not record: return ["protected trust-root files changed without a transition record: "+", ".join(actual)]
    declared=sorted(set(record.get("paths",[])))
    if declared!=actual: errors.append("transition paths do not exactly match protected files changed")
    expected_before=transition_digest(base,actual); expected_after=transition_digest(head,actual)
    if record.get("previousDigest")!=expected_before: errors.append("transition previousDigest does not match base protected content")
    if record.get("newDigest")!=expected_after: errors.append("transition newDigest does not match head protected content")
    return errors

def main():
    p=argparse.ArgumentParser(); p.add_argument("--base",required=True); p.add_argument("--head",default="HEAD"); p.add_argument("--record")
    a=p.parse_args(); policy=json.loads(POLICY.read_text()); record=json.loads(Path(a.record).read_text()) if a.record else None
    errors=verify(a.base,a.head,record,policy)
    print(json.dumps({"base":a.base,"head":a.head,"errors":errors},indent=2))
    return 1 if errors else 0
if __name__=="__main__": raise SystemExit(main())
