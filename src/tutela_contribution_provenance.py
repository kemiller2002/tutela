#!/usr/bin/env python3
"""Praxis contribution provenance (praxis.provenance/1) carried on Tutela records.

Tutela evidence already uses ``provenance`` for issuer/run attestation
(schemas/evidence.schema.json). Praxis contribution provenance -- who says they
discovered, remediated, measured, validated or reviewed something, and in which
execution -- is therefore carried under the separate field
``contributionProvenance`` (TUT-1707).

Contribution provenance is SELF-REPORTED and NON-AUTHORITATIVE (TUT-1708,
Praxis RQ-ROS-2026-A010/A019). Nothing in this module authenticates, authorizes,
weights or verifies anything; the release gate (src/tutela_gate.py) never reads
this field. This module only decides whether a received block may be carried:

- ``supported``: understood; preserved verbatim, unknown fields included.
- ``unsupported``: another major version; preserved verbatim, never interpreted.
- ``malformed``: the carrying record is invalid; rejected, never repaired.

The receiving and appending rules mirror the Praxis reference implementation
(lib/provenance-interchange.mjs at kemiller2002/praxis@c2657ef, contract revision 1.1) and are pinned
to the vendored conformance cases in tests/fixtures/praxis-provenance/.
Standard library only; every function is pure and never mutates its input.
"""
from __future__ import annotations
import argparse, copy, json, math, re, sys
from datetime import date
from pathlib import Path

FIELD = "contributionProvenance"
SCHEMA_TAG = "praxis.provenance/1"

_SCHEMA_PATTERN = re.compile(r"praxis\.provenance/([1-9][0-9]*)")
_EXECUTION_KEY = re.compile(r"EXE-[A-Za-z0-9._-]+")
_CONTRIBUTION_KEY = re.compile(r"CTB-[A-Za-z0-9._-]+")
_FOREIGN_EXECUTION_KEY = re.compile(r"EXT-([a-z][a-z0-9-]*)\.([A-Za-z0-9._-]+)")
_KIND = re.compile(r"agent|human|automation|unknown|x-[a-z0-9][a-z0-9-]*")
_OPERATION = re.compile(r"[a-z][a-z0-9-]*")
_EXTENSION = re.compile(r"x-[a-z0-9][a-z0-9-]*")
_TIMESTAMP = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,9})?Z")
_UNKNOWN = "unknown"

KNOWN_OPERATIONS = (
    "created", "modified", "reviewed", "approved", "superseded", "migrated",
    "discovered", "measured", "transformed", "remediated", "validated", "resolved",
)
_MODIFYING_OPERATIONS = frozenset({"modified", "superseded", "migrated", "transformed", "remediated", "resolved"})

_CREDENTIAL_PATTERNS = tuple(re.compile(p, flags) for p, flags in (
    (r"gh[pousr]_[A-Za-z0-9]{20,}", 0),
    (r"github_pat_[A-Za-z0-9_]{20,}", 0),
    (r"sk-[A-Za-z0-9_-]{20,}", 0),
    (r"AKIA[0-9A-Z]{16}", 0),
    (r"xox[abprs]-[A-Za-z0-9-]{10,}", 0),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", 0),
    (r"\bbearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.", 0),
))


class ContributionProvenanceError(ValueError):
    """A malformed contribution provenance block; the carrying record is invalid."""
    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__("malformed contributionProvenance: " + "; ".join(self.problems))


def _is_object(value): return isinstance(value, dict)
def _is_string(value): return isinstance(value, str)
def _is_non_empty_string(value): return _is_string(value) and value.strip() != ""
def _is_known(value): return _is_non_empty_string(value) and value.strip() != _UNKNOWN
def _js(value): return "undefined" if value is None else str(value)


def _parse_millis(value):
    """Milliseconds since the epoch for a calendar-valid UTC timestamp (year 0001-9999, no
    rollover such as Feb 30 or 24:00), or None. Extra fractional digits are truncated, never
    rounded, so ordering is compared at millisecond precision (contract revision 1.1).
    Never raises."""
    if not _is_string(value): return None
    m = _TIMESTAMP.fullmatch(value)
    if not m: return None
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    millis = int(((m.group(7) or ".")[1:] + "000")[:3])
    if year < 1 or hour > 23 or minute > 59 or second > 59: return None
    try: days = date(year, month, day).toordinal() - date(1970, 1, 1).toordinal()
    except ValueError: return None
    return (((days * 24 + hour) * 60 + minute) * 60 + second) * 1000 + millis


def _is_timestamp(value): return _parse_millis(value) is not None
def _instant(value):
    millis = _parse_millis(value)
    return math.inf if millis is None else millis


def is_credential_like(value): return any(p.search(value) for p in _CREDENTIAL_PATTERNS)


def credential_findings(node, path=""):
    """Dotted paths of every key or string value that looks like a credential."""
    if _is_string(node): return [path] if is_credential_like(node) else []
    if isinstance(node, list):
        return [f for i, item in enumerate(node) for f in credential_findings(item, f"{path}[{i}]")]
    if _is_object(node):
        found = []
        for key, value in node.items():
            child = f"{path}.{key}" if path else key
            found += ([child] if is_credential_like(key) else []) + credential_findings(value, child)
        return found
    return []


def key_kind(key):
    if _EXECUTION_KEY.fullmatch(key): return "execution"
    if _FOREIGN_EXECUTION_KEY.fullmatch(key): return "foreign-execution"
    if _CONTRIBUTION_KEY.fullmatch(key): return "contribution"
    return "invalid"


def actor_problems(actor, prefix="actor"):
    if not _is_object(actor): return [f"{prefix} must be an object"]
    problems = []
    kind = actor.get("kind")
    if not (_is_string(kind) and _KIND.fullmatch(kind)):
        problems.append(f"{prefix}.kind '{_js(kind)}' is not agent, human, automation, unknown, or x-...")
    if not _is_non_empty_string(actor.get("id")):
        problems.append(f"{prefix}.id must not be empty; use 'unknown' when it is not known")
    for field in ("provider", "model", "runtime"):
        if field in actor and not _is_non_empty_string(actor[field]):
            problems.append(f"{prefix}.{field} must be a non-empty string")
        if kind == "agent" and field not in actor:
            problems.append(f"{prefix}.{field} is required for an agent ('unknown' when not known)")
    return problems


def actors_agree(left, right):
    """Same actor: kind, stable id and every known attribute agree; 'unknown' never contradicts."""
    def compatible(a, b): return not (_is_known(a) and _is_known(b)) or a == b
    return (left.get("kind") == right.get("kind")
            and (left.get("id") == right.get("id") or not _is_known(left.get("id")) or not _is_known(right.get("id")))
            and all(compatible(left.get(f), right.get(f)) for f in ("provider", "model", "runtime")))


def _string_list_problems(container, field, label):
    if field not in container: return []
    value = container[field]
    return [] if isinstance(value, list) and all(_is_non_empty_string(v) for v in value) else [f"{label} must be an array of non-empty strings"]


def contribution_problems(key, entry):
    prefix = f"contributions.{key}"
    if not _is_object(entry): return [f"{prefix} must be an object"]
    problems = []
    kind = key_kind(key)
    if kind == "invalid": problems.append(f"{prefix}: key must be EXE-..., EXT-<system>.<run-id>, or CTB-...")
    operations = entry.get("operations")
    if not isinstance(operations, list): problems.append(f"{prefix}.operations must be an array")
    elif not operations: problems.append(f"{prefix}.operations must record at least one operation")
    else:
        problems += [f"{prefix}.operations: '{op}' is not a valid operation code"
                     for op in operations if not (_is_string(op) and _OPERATION.fullmatch(op))]
        if len({json.dumps(op, sort_keys=True) for op in operations}) != len(operations):
            problems.append(f"{prefix}.operations must not repeat an operation")
    if not _is_timestamp(entry.get("at")): problems.append(f"{prefix}.at must be a calendar-valid ISO-8601 UTC timestamp")
    if "last" in entry:
        last = entry["last"]
        if not _is_timestamp(last): problems.append(f"{prefix}.last must be a calendar-valid ISO-8601 UTC timestamp")
        elif _instant(last) < _instant(entry.get("at")): problems.append(f"{prefix}.last must not precede at")
    if "actor" not in entry: problems.append(f"{prefix}.actor is required")
    else: problems += actor_problems(entry["actor"], f"{prefix}.actor")
    actor = entry.get("actor")
    if _is_object(actor) and actor.get("kind") == "agent" and kind not in ("execution", "foreign-execution"):
        problems.append(f"{prefix}: an agent contribution must be keyed by the execution (EXE-... or EXT-...) that produced it")
    if "reason" in entry and not _is_string(entry["reason"]): problems.append(f"{prefix}.reason must be a string")
    problems += _string_list_problems(entry, "evidence", f"{prefix}.evidence")
    return problems


def _creators(contributions):
    return [(k, e) for k, e in contributions.items() if "created" in e.get("operations", [])]


def _history_problems(contributions):
    created = _creators(contributions)
    if len(created) > 1: return ["more than one contribution claims 'created': " + ", ".join(k for k, _ in created)]
    if not created: return []
    creation_key, creation = created[0]
    return [f"contributions.{k} precedes the recorded creation ({creation_key})"
            for k, e in contributions.items() if k != creation_key and _instant(e.get("at")) < _instant(creation.get("at"))]


def _verdict(verdict, problems=(), warnings=(), schema=None):
    return {"verdict": verdict, "problems": list(problems), "warnings": list(warnings), **({"schema": schema} if schema else {})}


def classify(block):
    """Classify a received block as supported, unsupported or malformed (never mutates it, never raises).
    Any unexpected parse failure is reported as malformed rather than crashing the boundary."""
    try: return _classify(block)
    except (ValueError, TypeError, OverflowError, RecursionError) as error:
        return _verdict("malformed", [f"provenance could not be read: {type(error).__name__}"])


def _classify(block):
    if not _is_object(block): return _verdict("malformed", ["provenance must be a JSON object"])
    secrets = credential_findings(block)
    if secrets:
        return _verdict("malformed", [f"{p}: credential-like value; provenance must never carry authentication material" for p in secrets])
    if "schema" in block:
        schema = block["schema"]
        if not _is_string(schema): return _verdict("malformed", ["schema must be a string"])
        if schema != SCHEMA_TAG:
            if _SCHEMA_PATTERN.fullmatch(schema): return _verdict("unsupported", schema=schema)
            return _verdict("malformed", [f"schema '{schema}' is not a valid praxis.provenance/<major> tag"])
    contributions = block.get("contributions")
    if not _is_object(contributions):
        return _verdict("malformed", ["contributions is required" if "contributions" not in block
                                      else "contributions must be an object keyed by EXE-, EXT-, or CTB- keys"])
    problems = [p for k, e in contributions.items() for p in contribution_problems(k, e)]
    problems += _string_list_problems(block, "derivedFrom", "derivedFrom")
    if problems: return _verdict("malformed", problems)
    invariant = _history_problems(contributions)
    if invariant: return _verdict("malformed", invariant)
    warnings = [f"contributions.{k}.operations: '{op}' is not an operation this version knows; preserved verbatim"
                for k, e in contributions.items() for op in e["operations"]
                if op not in KNOWN_OPERATIONS and not _EXTENSION.fullmatch(op)]
    return _verdict("supported", warnings=warnings)


def empty_block(): return {"schema": SCHEMA_TAG, "contributions": {}}


def append_contribution(block, key, contribution):
    """Append one contribution under Praxis append-only rules.
    Returns {"ok": True, "block", "changed"} or {"ok": False, "error"}; the input is never mutated."""
    received = classify(block)
    if received["verdict"] != "supported":
        suffix = f" ({received['schema']})" if received.get("schema") else ""
        return _refuse(f"refusing to append to a {received['verdict']} provenance block{suffix}")
    secrets = credential_findings({key: contribution})
    if secrets: return _refuse(", ".join(secrets) + ": credential-like value; provenance must never carry authentication material")
    problems = contribution_problems(key, contribution)
    if problems: return _refuse("; ".join(problems))
    nxt = copy.deepcopy(block)
    existing = nxt["contributions"].get(key)
    ops = contribution["operations"]
    if existing is None:
        if "created" in ops:
            if _creators(nxt["contributions"]):
                return _refuse("the record already has an originator; record 'modified' instead of 'created'")
            if any(_instant(e.get("at")) < _instant(contribution["at"]) for e in nxt["contributions"].values()):
                return _refuse("a 'created' contribution cannot follow existing contributions")
        nxt["contributions"][key] = copy.deepcopy(contribution)
        return _finish(nxt, True)
    if not actors_agree(existing["actor"], contribution["actor"]):
        return _refuse(f"contribution '{key}' is already attributed to {existing['actor'].get('kind')}:{existing['actor'].get('id')}; refusing to re-attribute it")
    # An actor with unknown identity cannot extend an entry a known actor holds.
    if ((_is_known(existing["actor"].get("id")) and not _is_known(contribution["actor"].get("id")))
            or (existing["actor"].get("kind") != _UNKNOWN and contribution["actor"].get("kind") == _UNKNOWN)):
        return _refuse(f"contribution '{key}' belongs to {existing['actor'].get('kind')}:{existing['actor'].get('id')}; an actor with unknown identity cannot extend it")
    if "created" in ops and "created" not in existing["operations"]:
        earlier = any(other != key and _instant(e.get("at")) < _instant(existing.get("at")) for other, e in nxt["contributions"].items())
        if _creators(nxt["contributions"]) or earlier:
            return _refuse("the record's originator is already recorded or precedes this contribution; record 'modified' instead of 'created'")
    operations = existing["operations"] + [op for op in ops if op not in existing["operations"]]
    prior_evidence = existing.get("evidence", [])
    evidence = prior_evidence + [x for x in contribution.get("evidence", []) if x not in prior_evidence]
    candidates = [existing.get("last", existing.get("at")), contribution.get("last", contribution.get("at"))]
    latest = candidates[1] if _instant(candidates[1]) > _instant(candidates[0]) else candidates[0]
    # Unknown fields from the incoming contribution are kept; the existing entry wins on conflict.
    merged = {**copy.deepcopy(contribution), **existing, "operations": operations,
              **({"evidence": evidence} if evidence else {}),
              **({"last": latest} if _instant(latest) > _instant(existing.get("at")) else {}),
              **({"reason": contribution["reason"]} if "reason" not in existing and "reason" in contribution else {})}
    changed = json.dumps(merged) != json.dumps(existing)
    nxt["contributions"][key] = merged
    return _finish(nxt, changed)


def _refuse(error): return {"ok": False, "error": error}


def _finish(block, changed):
    """Contract 1.1: whatever an append returns must itself classify as supported."""
    result = classify(block)
    if result["verdict"] != "supported":
        return _refuse(f"the resulting history would be {result['verdict']}: " + "; ".join(result["problems"]))
    return {"ok": True, "block": block, "changed": changed}


def add_lineage(block, references):
    """Add lineage references (never authorship), preserving existing order."""
    current = block.get("derivedFrom") if isinstance(block.get("derivedFrom"), list) else []
    additions = [r for r in references if r not in current]
    return copy.deepcopy(block) if not additions else {**copy.deepcopy(block), "derivedFrom": current + additions}


def preservation_violations(before, after):
    """Everything `before` held that `after` lost or rewrote (empty when faithful)."""
    if classify(before)["verdict"] == "unsupported":
        return [] if before == after else ["unsupported provenance was altered instead of carried verbatim"]
    if not (_is_object(after) and _is_object(after.get("contributions"))): return ["provenance was removed"]
    violations = []
    for key, entry in (before.get("contributions") or {}).items():
        later = after["contributions"].get(key)
        if later is None: violations.append(f"contribution {key} was removed"); continue
        if later.get("actor") != entry.get("actor"): violations.append(f"contribution {key} actor was overwritten")
        if later.get("at") != entry.get("at"): violations.append(f"contribution {key} time was rewritten")
        violations += [f"contribution {key} lost operation {op}" for op in entry.get("operations", []) if op not in later.get("operations", [])]
        violations += [f"contribution {key} lost evidence {x}" for x in entry.get("evidence", []) if x not in later.get("evidence", [])]
        violations += [f"contribution {key} lost field {f}" for f in entry if f not in later]
    violations += [f"block lost field {f}" for f in before if f not in after]
    violations += [f"lineage {r} was removed" for r in before.get("derivedFrom", []) if r not in after.get("derivedFrom", [])]
    creators_before = [k for k, _ in _creators(before.get("contributions") or {})]
    creators_after = [k for k, _ in _creators(after["contributions"])]
    if len(creators_before) == 1 and creators_before != creators_after: violations.append("the originator was replaced")
    return violations


def originator(block):
    """The originating ('created') contribution, or None when origin is not recorded."""
    found = _creators(block.get("contributions") or {})
    return {"key": found[0][0], **found[0][1]} if len(found) == 1 else None


def modifiers(block):
    """Contributions that changed the record after its creation."""
    return [{"key": k, "actor": e["actor"]} for k, e in (block.get("contributions") or {}).items()
            if "created" not in e["operations"]
            and any(op in _MODIFYING_OPERATIONS or op not in KNOWN_OPERATIONS for op in e["operations"])]


def with_role(block, operation):
    """Contributions that played a role (for example 'validated'), in time order."""
    found = [(k, e) for k, e in (block.get("contributions") or {}).items() if operation in e["operations"]]
    return [{"key": k, "actor": e["actor"], "at": e["at"]} for k, e in sorted(found, key=lambda item: _instant(item[1]["at"]))]


# --- Tutela boundary -------------------------------------------------------------------

def accept(block):
    """Validate a block for carrying on a Tutela record. Returns (verbatim copy, classification);
    raises ContributionProvenanceError when malformed. Unsupported majors are carried verbatim."""
    result = classify(block)
    if result["verdict"] == "malformed": raise ContributionProvenanceError(result["problems"])
    return copy.deepcopy(block), result


def attach(record, block):
    """A new record carrying `block` verbatim under contributionProvenance (validated first)."""
    carried, _ = accept(block)
    return {**copy.deepcopy(record), FIELD: carried}


def read(record):
    """Classification of a record's contributionProvenance; records without one read as
    'unattributed' (legacy or not recorded; nothing is inferred)."""
    if not _is_object(record) or FIELD not in record: return _verdict("unattributed")
    return classify(record[FIELD])


def record_problems(record, label="record"):
    """Problems that make a record invalid because its contributionProvenance is malformed."""
    result = read(record)
    return [f"{label}.{FIELD}: {p}" for p in result["problems"]] if result["verdict"] == "malformed" else []


def assessment_problems(assessment):
    """Malformed contributionProvenance on an assessment or any of its structured evidence entries."""
    if not _is_object(assessment): return []
    problems = record_problems(assessment, "assessment")
    evidence = assessment.get("evidence")
    for i, item in enumerate(evidence if isinstance(evidence, list) else []):
        if _is_object(item): problems += record_problems(item, f"evidence[{i}]({item.get('id', '?')})")
    return problems


def main(argv=None):
    p = argparse.ArgumentParser(description="Check contributionProvenance on a Tutela evidence record or assessment. Non-authoritative: this never affects posture.")
    p.add_argument("document", help="evidence record or security assessment JSON")
    args = p.parse_args(argv)
    doc = json.loads(Path(args.document).read_text())
    problems = assessment_problems(doc) if _is_object(doc) and "invariantResults" in doc else record_problems(doc, "evidence")
    print(json.dumps({"valid": not problems, "problems": problems}, indent=2))
    return 2 if problems else 0


if __name__ == "__main__": raise SystemExit(main())
