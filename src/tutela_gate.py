#!/usr/bin/env python3
"""Tutela semantic validator and deterministic release-posture gate.

CONFORMANCE ORACLE ONLY. The authoritative gate is the F# implementation
(src/Tutela.Core, CLI src/Tutela.Cli); see docs/decisions/0001-gate-authority.md.
This module is retained under an expiring migration bridge so the F# port can
be compared against it (tests/parity). Do not add production behavior here.

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
DEFAULT_AUTHORITY_POLICY=Path(__file__).resolve().parents[1]/"security"/"PROVENANCE-AUTHORITY.json"
DEFAULT_TRUST_ROOT_POLICY=Path(__file__).resolve().parents[1]/"security"/"TRUST-ROOT-CHANGE.json"
DEFAULT_ROLE_REGISTRY=Path(__file__).resolve().parents[1]/"security"/"ROLE-REGISTRY.json"
DEFAULT_SENSITIVE_CATALOG=Path(__file__).resolve().parents[1]/"security"/"SENSITIVE-DATA-RULES.json"
# Exception approval: accepting risk is a security-owner decision by a human
# (TUT-1103). Mirrors Tutela.Core.ExceptionApproval; see tests/parity.
EXCEPTION_APPROVER_ROLE="security-owner"
IDENTITY_KINDS={"human","agent","workflow"}

def load_sensitive_catalog(path=None):
    """Sensitive-data rules are owned by security/SENSITIVE-DATA-RULES.json (single owner)."""
    import re
    c=json.loads(Path(path or DEFAULT_SENSITIVE_CATALOG).read_text())
    return {"keys":[(r["id"],{k.lower() for k in r["keys"]}) for r in c["keyRules"]],
            "values":[(r["id"],re.compile(r["pattern"])) for r in c["valueRules"]]}

_SENSITIVE=None
def sensitive_catalog():
    global _SENSITIVE
    if _SENSITIVE is None: _SENSITIVE=load_sensitive_catalog()
    return _SENSITIVE

def load_role_registry(path=None):
    return json.loads(Path(path or DEFAULT_ROLE_REGISTRY).read_text())

def identity_binding_valid(identity):
    if not (isinstance(identity,dict) and identity.get("provider") and str(identity.get("subjectId","")).isdigit() and identity.get("bindingVerified") is True): return False
    evidence=identity.get("bindingEvidence") or []
    if identity.get("provider")=="github":
        return any(isinstance(e,dict) and e.get("kind")=="platform-api-observation" and e.get("issuer")=="github" and e.get("sourceRef") and e.get("observedAt") for e in evidence)
    return False

def registered_roles(identity, registry, at=None):
    at=at or now_utc(); roles=set()
    if registry.get("default") != "deny" or not identity_binding_valid(identity): return roles
    for m in registry.get("memberships",[]):
        mi=m.get("identity") or {}
        if not identity_binding_valid(mi): continue
        if mi.get("provider") != identity.get("provider") or str(mi.get("subjectId")) != str(identity.get("subjectId")): continue
        try:
            vf=parse_time(m.get("validFrom")); vu=parse_time(m.get("validUntil"))
            if vf and vf > at: continue
            if vu and vu <= at: continue
        except ValueError: continue
        roles.update(m.get("roles",[]))
    return roles

def load_trust_root_policy(path=None):
    return json.loads(Path(path or DEFAULT_TRUST_ROOT_POLICY).read_text())

def approval_authorized(approval, trust_policy, role_registry, weakening=False, at=None):
    identity=approval.get("approverIdentity") or {}
    role=approval.get("role")
    if role not in registered_roles(identity,role_registry,at): return False
    for rule in trust_policy.get("approvalAuthorities",[]):
        if (identity.get("kind") in rule.get("identityKinds",[])
            and role in rule.get("roles",[])
            and "trust-root-change" in rule.get("mayApprove",[])
            and (not weakening or rule.get("mayAuthorizeWeakening") is True)):
            return True
    return False

def valid_digest(d):
    if not isinstance(d,dict) or d.get("algorithm") not in {"sha256","sha512"}: return False
    v=d.get("value",""); expected=64 if d.get("algorithm")=="sha256" else 128
    return len(v)==expected and all(ch in "0123456789abcdefABCDEF" for ch in v)

def validate_trust_root_change(change, trust_policy, role_registry, at=None):
    errors=[]
    if not change: return errors
    protected=set(trust_policy.get("protectedPaths",[]))
    touched=set(change.get("paths",[]))
    if not (protected & touched): return errors
    for k in ("id","rationale","changedBy","changedByIdentity","previousDigest","newDigest"):
        if not change.get(k): errors.append(f"trustRootChange.{k} is required")
    for name in ("previousDigest","newDigest"):
        if change.get(name) and not valid_digest(change.get(name)): errors.append(f"trustRootChange.{name} must be an exact sha256/sha512 digest")
    if change.get("previousDigest")==change.get("newDigest") and change.get("previousDigest"):
        errors.append("trustRootChange digests must describe an actual transition")
    approvals=change.get("approvals") or []
    independent=[x for x in approvals if isinstance(x,dict) and x.get("approved") is True and x.get("approverIdentity") and x.get("evidence") and str(x.get("approverIdentity",{}).get("subjectId")) != str((change.get("changedByIdentity") or {}).get("subjectId")) and approval_authorized(x,trust_policy,role_registry,False,at)]
    if len(independent) < int(trust_policy.get("requirements",{}).get("approvalsMinimum",1)):
        errors.append("protected trust-root change requires independent approval evidence")
    if change.get("weakening") is True:
        if change.get("weakeningExplicitlyAuthorized") is not True:
            errors.append("trust-root weakening requires explicit authorization")
        weakening_approvals=[x for x in independent if approval_authorized(x,trust_policy,role_registry,True,at)]
        if not weakening_approvals:
            errors.append("trust-root weakening requires an authorized security-owner approval")
    return errors

def load_authority_policy(path=None):
    return json.loads(Path(path or DEFAULT_AUTHORITY_POLICY).read_text())

def evidence_authorized(e, authority_policy):
    identity=e.get("producerIdentity") or {}; provenance=e.get("provenance") or {}
    for rule in authority_policy.get("authorities",[]):
        if (e.get("type") in rule.get("evidenceTypes",[])
            and provenance.get("kind") in rule.get("provenanceKinds",[])
            and provenance.get("issuer") in rule.get("issuers",[])
            and identity.get("type") in rule.get("producerIdentityTypes",[])):
            return True, rule.get("id")
    return False, None

def now_utc(): return datetime.now(timezone.utc)

def parse_time(value):
    if not value: return None
    return datetime.fromisoformat(value.replace("Z","+00:00"))

def sensitive_match(value, catalog=None):
    """Depth-first ('field'|'value', rule id) for the first sensitive key or value, else None."""
    catalog=catalog or sensitive_catalog()
    if isinstance(value,dict):
        for k,v in value.items():
            for rid,keys in catalog["keys"]:
                if isinstance(k,str) and k.lower() in keys: return ("field",rid)
            m=sensitive_match(v,catalog)
            if m: return m
        return None
    if isinstance(value,list):
        for v in value:
            m=sensitive_match(v,catalog)
            if m: return m
        return None
    if isinstance(value,str):
        for rid,rx in catalog["values"]:
            if rx.search(value): return ("value",rid)
    return None

def contains_sensitive_value(value, key=None):
    return sensitive_match({key:value} if key else value) is not None

def validate(a, authority_policy=None, trust_policy=None, role_registry=None, at=None):
    errors=[]
    trust_policy=trust_policy or load_trust_root_policy()
    role_registry=role_registry or load_role_registry()
    if role_registry.get("default") != "deny": errors.append("security role registry must default deny")
    errors.extend(validate_trust_root_change(a.get("trustRootChange"),trust_policy,role_registry,at))
    authority_policy=authority_policy or load_authority_policy()
    if authority_policy.get("default") != "deny": errors.append("provenance authority policy must default deny")
    if a.get("schemaVersion") != 1: errors.append("schemaVersion must be 1")
    policy=a.get("policy") or {}
    if policy:
        if not policy.get("id") or not policy.get("version"): errors.append("policy.id and policy.version are required when policy is supplied")
        if policy.get("allowGateWeakening") is True: errors.append("assessment cannot authorize gate weakening")
    sensitive=sensitive_match(a.get("evidence",[]))
    if sensitive: errors.append("evidence contains a sensitive "+sensitive[0])
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
            if x.get("state")=="Verified" and x.get("requiresIndependentVerification") is True:
                attestations=x.get("verifierAttestations") or []
                independent=[v for v in attestations if isinstance(v,dict) and v.get("independent") is True and v.get("verifier") and v.get("evidence")
                    and v.get("verifierIdentity") and v.get("separationBasis")]
                for v in independent:
                    vi=v.get("verifierIdentity") or {}
                    if not (isinstance(vi,dict) and vi.get("type") and vi.get("value")):
                        errors.append(f"{iid or p} independent verifier identity is incomplete")
                    if v.get("verifier")==x.get("implementedBy") or vi.get("value")==x.get("implementedBy"):
                        errors.append(f"{iid or p} verifier is not independent of implementer")
                if not independent:
                    errors.append(f"{iid or p} requires an independent verifier attestation")
    evidence_items=a.get("evidence",[])
    if not isinstance(evidence_items,list): errors.append("evidence must be an array when supplied")
    else:
        evidence_objects=[e for e in evidence_items if isinstance(e,dict)]
        evidence_ids=[e.get("id") if isinstance(e,dict) else e for e in evidence_items]
        if any(not isinstance(e,dict) for e in evidence_items):
            errors.append("evidence entries must be structured objects; bare evidence references are not sufficient")
        if len(evidence_ids) != len(set(evidence_ids)): errors.append("duplicate evidence id")
        known=set(evidence_ids)
        for e in evidence_objects:
            eid=e.get("id") or "evidence"
            for k in ("id","producer","producerIdentity","subjectRef","observedAt","artifactDigest","provenance"):
                if not e.get(k): errors.append(f"{eid}.{k} is required")
            digest=e.get("artifactDigest") or {}
            if isinstance(digest,dict) and digest and not (digest.get("algorithm") in {"sha256","sha512"} and digest.get("value") and len(digest.get("value","")) == (64 if digest.get("algorithm")=="sha256" else 128) and all(ch in "0123456789abcdefABCDEF" for ch in digest.get("value",""))):
                errors.append(f"{eid}.artifactDigest requires sha256/sha512 algorithm and value")
            provenance=e.get("provenance") or {}
            if isinstance(provenance,dict) and provenance and not (provenance.get("kind") and provenance.get("issuer") and provenance.get("runRef")):
                errors.append(f"{eid}.provenance requires kind, issuer and runRef")
            identity=e.get("producerIdentity") or {}
            authorized, authority_id=evidence_authorized(e,authority_policy)
            if not authorized:
                errors.append(f"{eid} provenance issuer is not authorized for evidence type and producer identity")
            if isinstance(identity,dict) and identity and not (identity.get("type") and identity.get("value")):
                errors.append(f"{eid}.producerIdentity requires type and value")
            if e.get("artifactDigest") and subject.get("artifactHash"):
                sd=subject.get("artifactHash")
                normalized=(sd.get("value") if isinstance(sd,dict) else sd)
                if normalized and e.get("artifactDigest",{}).get("value") != normalized:
                    errors.append(f"{eid} artifact digest does not match subject artifactHash")
            if e.get("subjectRef") and e.get("subjectRef") != subject.get("ref"):
                errors.append(f"{eid} is bound to a different subject ref")
            if e.get("invalidatedAt") and not e.get("invalidationReason"):
                errors.append(f"{eid} invalidation requires a reason")
        for x in inv or []:
            if isinstance(x,dict):
                for eid in (x.get("evidence") or [])+(x.get("contradictoryEvidence") or []):
                    if known and eid not in known: errors.append(f"{x.get('id','invariant')} references undeclared evidence {eid}")
    threat_ids=a.get("threats",[])
    if not isinstance(threat_ids,list): errors.append("threats must be an array when supplied")
    elif len(threat_ids) != len(set(threat_ids)): errors.append("duplicate threat id")
    exceptions=a.get("exceptions",[])
    if not isinstance(exceptions,list): errors.append("exceptions must be an array")
    else:
        for i,e in enumerate(exceptions):
            if not isinstance(e,dict): errors.append(f"exceptions[{i}] must be an object"); continue
            for k in ("id","approver","expiresAt"):
                if not e.get(k): errors.append(f"exceptions[{i}].{k} is required")
    return errors

def _aware_time(value):
    """An offset-qualified timestamp, or None. Naive times cannot be ordered and are rejected."""
    if not isinstance(value,str) or not value: return None
    try: t=parse_time(value)
    except ValueError: return None
    return t if t.tzinfo is not None else None

def _canonical_subject(identity):
    sid=identity.get("subjectId")
    if isinstance(sid,bool): return None
    if isinstance(sid,int): sid=str(sid)
    if not (isinstance(sid,str) and sid.isascii() and sid.isdigit() and sid[0]!="0" and len(sid)<=20 and int(sid)<=2**64-1): return None
    return sid

def exception_identity(identity):
    """A verified binding with a known kind and canonical subject id, else None."""
    if not identity_binding_valid(identity) or identity.get("kind") not in IDENTITY_KINDS: return None
    sid=_canonical_subject(identity)
    return (identity.get("provider"),sid) if sid else None

def _non_empty_strings(value):
    return [x for x in value if isinstance(x,str) and x] if isinstance(value,list) else []

def exception_rejections(e, role_registry=None, at=None):
    """Every reason exception `e` cannot satisfy a gate at `at`; empty means honored.

    Codes mirror Tutela.Core.ExceptionRejection. The approver must be a verified
    human identity, differ from the requester, and hold security-owner in the
    role registry at `at`; assessment role claims are not authoritative.
    """
    at=at or now_utc(); role_registry=role_registry or load_role_registry(); out=[]
    if e.get("approved") is not True: out.append("not-approved")
    expires=_aware_time(e.get("expiresAt")); created=_aware_time(e.get("createdAt"))
    if expires is None: out.append("invalid-expiry")
    elif expires<=at: out.append("expired")
    if created is None: out.append("invalid-creation")
    elif created>at: out.append("not-yet-valid")
    elif expires is not None and created>=expires: out.append("invalid-creation")
    rationale=e.get("rationale")
    if (not _non_empty_strings(e.get("covers")) or not (isinstance(rationale,str) and rationale.strip())
        or not _non_empty_strings(e.get("compensatingControls")) or not _non_empty_strings(e.get("evidence"))):
        out.append("incomplete-record")
    requester_raw=e.get("requestedByIdentity"); approver_raw=e.get("approverIdentity")
    requester=exception_identity(requester_raw) if isinstance(requester_raw,dict) else None
    approver=exception_identity(approver_raw) if isinstance(approver_raw,dict) else None
    if requester is None: out.append("requester-unbound")
    if approver is None: out.append("approver-unbound")
    else:
        if approver_raw.get("kind")!="human": out.append("approver-not-human")
        if requester is not None and requester==approver: out.append("self-approval")
        if EXCEPTION_APPROVER_ROLE not in registered_roles(approver_raw,role_registry,at): out.append("approver-lacks-role")
    return out

def valid_exceptions(a, at=None, role_registry=None):
    at=at or now_utc()
    return [e for e in a.get("exceptions",[]) if isinstance(e,dict) and not exception_rejections(e,role_registry,at)]

def derive(a, at=None, authority_policy=None, trust_policy=None, role_registry=None):
    at=at or now_utc()
    errors=validate(a,authority_policy,trust_policy,role_registry,at)
    if errors: return "INDETERMINATE", ["invalid assessment: "+x for x in errors]
    inv=a["invariantResults"]
    evidence_by_id={e.get("id"):e for e in a.get("evidence",[]) if isinstance(e,dict) and e.get("id")}
    derived_stale=set()
    for eid,e in evidence_by_id.items():
        if e.get("invalidatedAt"): derived_stale.add(eid)
        try:
            expires=parse_time(e.get("validUntil"))
            if expires and expires <= at: derived_stale.add(eid)
        except ValueError:
            return "INDETERMINATE", [f"invalid evidence time {eid}"]
    for x in inv:
        if x.get("state")=="Verified" and any(eid in derived_stale for eid in x.get("evidence",[])):
            return "INDETERMINATE", [f"{x['id']} relies on stale or invalidated evidence"]
    unknown_effects=a.get("unknownSecurityEffects",[])
    violated=[x["id"] for x in inv if x["state"]=="Violated"]
    unknown=[x["id"] for x in inv if x["state"]=="Unknown"]
    stale=[x["id"] for x in inv if x["state"]=="Stale"]
    missing=[x["id"] for x in inv if x["state"]=="Verified" and not x.get("evidence")]
    exceptions=valid_exceptions(a,at,role_registry)
    accepted=set()
    for e in exceptions: accepted.update(_non_empty_strings(e.get("covers")))
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
