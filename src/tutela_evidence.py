#!/usr/bin/env python3
"""Create a digest-bearing Tutela evidence record for an immutable subject artifact."""
from __future__ import annotations
import argparse, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
try:
    from src.tutela_contribution_provenance import accept, ContributionProvenanceError, FIELD as CONTRIBUTION_FIELD
except ImportError:  # executed as a script: python src/tutela_evidence.py
    from tutela_contribution_provenance import accept, ContributionProvenanceError, FIELD as CONTRIBUTION_FIELD

def digest_file(path, algorithm="sha256"):
    h=hashlib.new(algorithm)
    with Path(path).open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def load_contribution_provenance(path):
    """Read and validate a praxis.provenance/1 block (TUT-1707..TUT-1710).
    Malformed -> ContributionProvenanceError; unsupported majors are returned verbatim.
    The block is self-reported and never affects producerIdentity, provenance or authority."""
    try: block=json.loads(Path(path).read_text())
    except json.JSONDecodeError as e: raise ContributionProvenanceError([f"{path} is not JSON: {e}"])
    return accept(block)

def build(args):
    contribution=getattr(args,"contribution_provenance_block",None)
    observed=args.observed_at or datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
    return {"id":args.id,"type":args.type,"source":args.source,"subjectRef":args.subject_ref,
      "observedAt":observed,"producer":args.producer,
      "producerIdentity":{"type":args.producer_identity_type,"value":args.producer_identity_value},
      "artifactDigest":{"algorithm":args.algorithm,"value":digest_file(args.artifact,args.algorithm)},
      "provenance":{"kind":args.provenance_kind,"issuer":args.provenance_issuer,"runRef":args.run_ref,
                    **({"workflowRef":args.workflow_ref} if args.workflow_ref else {})},
      "method":f"{args.algorithm} digest of {Path(args.artifact).name}","redacted":True,
      "limitations":["Digest proves byte identity of the named artifact, not the truth or completeness of its claims."],
      "bundleDigest":({"algorithm":"sha256","value":bundle_digest.removeprefix("sha256:")} if (bundle_digest := getattr(args, "bundle_digest", None)) else None),
      **({CONTRIBUTION_FIELD:accept(contribution)[0]} if contribution is not None else {})}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("artifact"); p.add_argument("--id",required=True); p.add_argument("--type",default="Test")
    p.add_argument("--source",required=True); p.add_argument("--subject-ref",required=True); p.add_argument("--producer",required=True)
    p.add_argument("--producer-identity-type",required=True); p.add_argument("--producer-identity-value",required=True)
    p.add_argument("--provenance-kind",required=True); p.add_argument("--provenance-issuer",required=True); p.add_argument("--run-ref",required=True)
    p.add_argument("--workflow-ref"); p.add_argument("--bundle-digest"); p.add_argument("--observed-at"); p.add_argument("--algorithm",choices=["sha256","sha512"],default="sha256")
    p.add_argument("--contribution-provenance",metavar="PATH",help="attach a Praxis praxis.provenance/1 block (self-reported, non-authoritative) as contributionProvenance; malformed blocks are rejected before anything is written")
    p.add_argument("--output")
    args=p.parse_args()
    if args.contribution_provenance:
        try: args.contribution_provenance_block,result=load_contribution_provenance(args.contribution_provenance)
        except ContributionProvenanceError as e: p.error(str(e))
        for w in result["warnings"]: print(f"warning: contributionProvenance {w}",file=sys.stderr)
        if result["verdict"]=="unsupported": print(f"warning: contributionProvenance uses {result['schema']}; carried verbatim, not interpreted",file=sys.stderr)
    payload=json.dumps(build(args),indent=2)+"\n"
    if args.output: Path(args.output).write_text(payload)
    else: print(payload,end="")
if __name__=="__main__": main()
