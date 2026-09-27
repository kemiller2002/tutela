#!/usr/bin/env python3
"""Non-destructive Tutela bootstrap for another repository."""
from __future__ import annotations
import argparse, json
from pathlib import Path\n\nTUTELA_VERSION="0.2.0"\nINSTALL_SCHEMA_VERSION=1

def templates(repository, ref):
    assessment={"schemaVersion":1,"subject":{"repository":repository,"ref":ref},"posture":"INDETERMINATE",
      "scope":["initial Tutela bootstrap"],"invariantResults":[{"id":"SEC-INV-BOOTSTRAP","state":"Unknown","evidence":[]}],
      "unknownSecurityEffects":["SEC-UNK-BOOTSTRAP-REVIEW"],"exceptions":[],
      "limitations":["Bootstrap state requires repository-specific threat modeling and invariant definition."]}
    campaign={"schemaVersion":1,"id":"ADV-BOOTSTRAP-001","subject":{"repository":repository,"ref":ref},
      "scope":["initial adversarial coverage planning"],"environment":"local-test",
      "scenarios":[],"unknownCoverage":["No repository-specific adversarial scenarios have been defined."],
      "limitations":["Bootstrap campaign is intentionally non-executable until attack surfaces and authorization are defined."]}
    workflow="""name: Tutela Security Gate
on:
  pull_request:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  tutela:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Tutela assessment gate
        run: python3 .tutela/runtime/tutela_gate.py .tutela/security-assessment.json --check-declared
"""
    return {".tutela/security-assessment.json":json.dumps(assessment,indent=2)+"\n",
      ".tutela/adversarial-campaign.json":json.dumps(campaign,indent=2)+"\n",
      ".github/workflows/tutela-security.yml":workflow}

def install(root,repository,ref,force=False):
    root=Path(root); written=[]; preserved=[]
    for rel,content in templates(repository,ref).items():
        p=root/rel
        if p.exists() and not force: preserved.append(rel); continue
        p.parent.mkdir(parents=True,exist_ok=True); p.write_text(content); written.append(rel)
    runtime=root/".tutela/runtime"; runtime.mkdir(parents=True,exist_ok=True)
    source=Path(__file__).with_name("tutela_gate.py")
    target=runtime/"tutela_gate.py"
    if target.exists() and not force: preserved.append(".tutela/runtime/tutela_gate.py")
    else: target.write_text(source.read_text()); written.append(".tutela/runtime/tutela_gate.py")
    return {"written":written,"preserved":preserved}

def main(argv=None):
    p=argparse.ArgumentParser(description="Bootstrap Tutela into a repository without overwriting existing configuration")
    p.add_argument("root"); p.add_argument("--repository",required=True); p.add_argument("--ref",default="HEAD"); p.add_argument("--force",action="store_true")
    a=p.parse_args(argv); print(json.dumps(install(a.root,a.repository,a.ref,a.force),indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
