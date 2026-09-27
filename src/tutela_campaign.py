#!/usr/bin/env python3
"""CLI for bounded Tutela adversarial campaigns."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from src.tutela_orchestrator import execute_campaign, evidence_record

EXIT_OK=0
EXIT_VIOLATED=2
EXIT_INDETERMINATE=3
EXIT_INPUT=4

def load(path): return json.loads(Path(path).read_text())
def exit_for(bundle):
    outcomes={x.get("outcome") for x in bundle.get("results",[])}
    if "VIOLATED" in outcomes: return EXIT_VIOLATED
    if "INDETERMINATE" in outcomes or bundle.get("unknownCoverage"): return EXIT_INDETERMINATE
    return EXIT_OK

def main(argv=None):
    p=argparse.ArgumentParser(description="Run an explicitly authorized Tutela adversarial campaign")
    p.add_argument("campaign"); p.add_argument("authorization")
    p.add_argument("--bundle-out"); p.add_argument("--evidence-out")
    args=p.parse_args(argv)
    try:
        campaign=load(args.campaign); authorization=load(args.authorization)
        bundle=execute_campaign(campaign,authorization)
    except (OSError,ValueError,KeyError,TypeError,RuntimeError) as exc:
        print(json.dumps({"error":"campaign not executed","errorType":type(exc).__name__}),file=sys.stderr)
        return EXIT_INPUT
    rendered=json.dumps(bundle,indent=2,sort_keys=True)
    if args.bundle_out: Path(args.bundle_out).write_text(rendered+"\n")
    else: print(rendered)
    if args.evidence_out: Path(args.evidence_out).write_text(json.dumps(evidence_record(bundle),indent=2,sort_keys=True)+"\n")
    return exit_for(bundle)

if __name__=="__main__": raise SystemExit(main())
