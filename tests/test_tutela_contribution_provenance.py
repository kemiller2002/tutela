"""Praxis contribution provenance on Tutela records (TUT-1707..TUT-1712).

Conformance: every vendored Praxis case (tests/fixtures/praxis-provenance/cases.json)
and the Echelon end-to-end chain are replayed against src/tutela_contribution_provenance.py.
"""
import copy, hashlib, json, subprocess, sys, tempfile, unittest
from argparse import Namespace
from pathlib import Path
from src import tutela_contribution_provenance as cp
from src.tutela_evidence import build

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "praxis-provenance"
VENDORED_SCHEMAS = ROOT / "schemas" / "vendor" / "praxis"
CASES = json.loads((FIXTURES / "cases.json").read_text())["cases"]
CHAIN = json.loads((FIXTURES / "echelon-chain.json").read_text())

A = {"kind": "agent", "id": "openai/codex", "provider": "openai", "model": "gpt-5-codex", "runtime": "codex"}
B = {"kind": "agent", "id": "anthropic/claude-code", "provider": "anthropic", "model": "unknown", "runtime": "claude-code"}
H = {"kind": "human", "id": "kevin"}
CI = {"kind": "automation", "id": "github/github-actions", "provider": "github", "model": "unknown", "runtime": "github-actions"}
U = {"kind": "unknown", "id": "unknown", "provider": "unknown", "model": "unknown", "runtime": "unknown"}
AEGIS = {"kind": "automation", "id": "echelon/aegis", "provider": "echelon", "model": "unknown", "runtime": "aegis"}
def t(minute): return f"2026-09-26T08:{minute:02d}:00.000Z"
def ok(result):
    assert result["ok"], result.get("error")
    return result["block"]


def evidence_args(artifact, **extra):
    return Namespace(artifact=str(artifact), id="SEC-EVD-100", type="Test", source="fixture", subject_ref="abc123", producer="CI",
                     producer_identity_type="workflow", producer_identity_value="tutela-foundation", provenance_kind="ci",
                     provenance_issuer="github-actions", run_ref="run-1", workflow_ref="wf@sha", observed_at="2026-09-25T00:00:00Z",
                     algorithm="sha256", **extra)


class VendoredSourceTests(unittest.TestCase):
    def test_vendored_files_match_recorded_sha256(self):
        for directory in (FIXTURES, VENDORED_SCHEMAS):
            source = json.loads((directory / "SOURCE.json").read_text())
            self.assertEqual("kemiller2002/praxis", source["repository"])
            self.assertEqual("c2657efb4d54f11d0fd0617cc1bcd5b8418601d5", source["commit"])
            for name, expected in source["files"].items():
                with self.subTest(file=str(directory / name)):
                    self.assertEqual(expected, hashlib.sha256((directory / name).read_bytes()).hexdigest())

    def test_all_contract_1_1_cases_are_present(self):
        self.assertEqual(56, len(CASES))

    def test_tutela_never_reads_identity_environment_variables(self):
        """Rules 7-8 (identity environment scrubbing, ROS_EXECUTION_ID inheritance) apply to launchers.
        Tutela launches no process for another actor and discovers no identity from the environment;
        pin that so a future change has to revisit the vendored list."""
        names = json.loads((FIXTURES / "identity-environment.json").read_text())["variables"]
        self.assertIn("ROS_EXECUTION_ID", names)
        for source in sorted((ROOT / "src").glob("*.py")):
            text = source.read_text()
            self.assertEqual([], [n for n in names if n in text], source.name)


class ConformanceTests(unittest.TestCase):
    def test_every_vendored_case_reaches_the_reference_verdict(self):
        for case in CASES:
            with self.subTest(case=case["name"]):
                result = cp.classify(case["block"])
                self.assertEqual(case["expect"], result["verdict"], result["problems"])
                self.assertEqual(case["warnings"], len(result["warnings"]))

    def test_classification_never_mutates_input(self):
        for case in CASES:
            before = json.dumps(case["block"], sort_keys=True)
            cp.classify(case["block"])
            self.assertEqual(before, json.dumps(case["block"], sort_keys=True))


class AppendingTests(unittest.TestCase):
    def test_second_contributor_never_overwrites_originator(self):
        created = ok(cp.append_contribution(cp.empty_block(), "EXE-1", {"operations": ["created"], "at": t(0), "actor": A}))
        modified = ok(cp.append_contribution(created, "EXE-2", {"operations": ["modified"], "at": t(5), "actor": B}))
        self.assertEqual([], cp.preservation_violations(created, modified))
        self.assertEqual("openai/codex", cp.originator(modified)["actor"]["id"])
        self.assertEqual(["anthropic/claude-code"], [m["actor"]["id"] for m in cp.modifiers(modified)])

    def test_second_or_late_creator_refused(self):
        created = ok(cp.append_contribution(cp.empty_block(), "EXE-1", {"operations": ["created"], "at": t(0), "actor": A}))
        self.assertFalse(cp.append_contribution(created, "EXE-2", {"operations": ["created"], "at": t(5), "actor": B})["ok"])
        modified_only = ok(cp.append_contribution(cp.empty_block(), "EXE-1", {"operations": ["modified"], "at": t(0), "actor": A}))
        self.assertFalse(cp.append_contribution(modified_only, "EXE-2", {"operations": ["created"], "at": t(5), "actor": B})["ok"])

    def test_execution_is_never_reattributed(self):
        block = ok(cp.append_contribution(cp.empty_block(), "EXE-1", {"operations": ["created"], "at": t(0), "actor": A}))
        self.assertFalse(cp.append_contribution(block, "EXE-1", {"operations": ["modified"], "at": t(5), "actor": B})["ok"])

    def test_two_executions_of_one_agent_stay_distinct(self):
        block = ok(cp.append_contribution(cp.empty_block(), "EXE-1", {"operations": ["discovered"], "at": t(0), "actor": A}))
        block = ok(cp.append_contribution(block, "EXE-2", {"operations": ["remediated"], "at": t(9), "actor": A}))
        self.assertEqual(["EXE-1", "EXE-2"], sorted(block["contributions"]))

    def test_same_execution_merges_and_is_idempotent(self):
        block = ok(cp.append_contribution(cp.empty_block(), "EXE-1", {"operations": ["discovered"], "at": t(0), "actor": A}))
        merged = cp.append_contribution(block, "EXE-1", {"operations": ["remediated"], "at": t(4), "actor": A})
        self.assertEqual(["discovered", "remediated"], merged["block"]["contributions"]["EXE-1"]["operations"])
        self.assertEqual(t(4), merged["block"]["contributions"]["EXE-1"]["last"])
        again = cp.append_contribution(merged["block"], "EXE-1", {"operations": ["remediated"], "at": t(4), "actor": A})
        self.assertFalse(again["changed"])

    def test_unsupported_major_is_never_appended_to(self):
        block = {"schema": "praxis.provenance/2", "shape": "future"}
        self.assertFalse(cp.append_contribution(block, "EXE-1", {"operations": ["reviewed"], "at": t(0), "actor": A})["ok"])

    def test_transformation_by_another_agent_preserves_history_and_unknown_fields(self):
        block = ok(cp.append_contribution(cp.empty_block(), "EXE-1", {"operations": ["created"], "at": t(0), "actor": A, "x-attestation": {"kind": "future"}}))
        block = {**block, "x-carrier": "kept"}
        after = ok(cp.append_contribution(block, "EXT-aegis.op-42", {"operations": ["transformed"], "at": t(3), "actor": B}))
        self.assertEqual([], cp.preservation_violations(block, after))
        self.assertEqual({"kind": "future"}, after["contributions"]["EXE-1"]["x-attestation"])
        self.assertEqual("kept", after["x-carrier"])

    def test_lineage_is_not_authorship(self):
        block = cp.add_lineage(ok(cp.append_contribution(cp.empty_block(), "EXE-1", {"operations": ["created"], "at": t(0), "actor": A})), ["aegis:finding/SF-0001"])
        self.assertEqual(["aegis:finding/SF-0001"], block["derivedFrom"])
        self.assertEqual("EXE-1", cp.originator(block)["key"])


def block_with(**entries):
    return {"schema": cp.SCHEMA_TAG, "contributions": entries}


def entry(at, actor=A, ops=("modified",), **extra):
    return {"operations": list(ops), "at": at, "actor": actor, **extra}


class ContractRevision11Tests(unittest.TestCase):
    """Regression tests for Praxis contract revision 1.1 (rules 1-5) and the round-2 review findings."""

    def verdict(self, block): return cp.classify(block)["verdict"]

    def test_year_zero_is_malformed_and_never_raises(self):
        for at in ("0000-01-01T00:00:00.000Z", "0000-02-29T00:00:00Z"):
            with self.subTest(at=at):
                self.assertEqual("malformed", self.verdict(block_with(**{"EXE-1": entry(at, ops=("created",))})))
                self.assertEqual("malformed", self.verdict(block_with(**{"EXE-1": entry(t(0), ops=("created",), last=at)})))

    def test_classify_never_raises_on_pathological_input(self):
        deep = {}; cursor = deep
        for _ in range(5000): cursor["x"] = {}; cursor = cursor["x"]
        self.assertEqual("malformed", self.verdict({"contributions": {}, "x-deep": deep}))

    def test_calendar_rollover_is_malformed(self):
        for at in ("2026-02-30T00:00:00Z", "2026-04-31T00:00:00Z", "2025-02-29T00:00:00Z", "2026-09-26T24:00:00Z", "2026-09-26T23:59:60Z", "2026-13-01T00:00:00Z"):
            with self.subTest(at=at):
                self.assertEqual("malformed", self.verdict(block_with(**{"EXE-1": entry(at)})))

    def test_extreme_valid_timestamps_are_supported(self):
        for at in ("9999-12-31T23:59:59.999999999Z", "0001-01-01T00:00:00Z", "2028-02-29T12:00:00Z"):
            with self.subTest(at=at):
                self.assertEqual("supported", self.verdict(block_with(**{"EXE-1": entry(at)})))

    def test_ordering_is_at_millisecond_precision(self):
        same_ms = entry("2026-09-26T08:00:00.0009Z", last="2026-09-26T08:00:00.0001Z")
        self.assertEqual("supported", self.verdict(block_with(**{"EXE-1": same_ms})))
        earlier_ms = entry("2026-09-26T08:00:00.002Z", last="2026-09-26T08:00:00.001999Z")
        self.assertEqual("malformed", self.verdict(block_with(**{"EXE-1": earlier_ms})))

    def test_json_null_never_means_absent(self):
        cases = {"schema": {"schema": None, "contributions": {}},
                 "last": block_with(**{"EXE-1": entry(t(0), last=None)}),
                 "reason": block_with(**{"EXE-1": entry(t(0), reason=None)}),
                 "evidence": block_with(**{"EXE-1": entry(t(0), evidence=None)}),
                 "derivedFrom": {**block_with(), "derivedFrom": None},
                 "actor.model": block_with(**{"EXE-1": entry(t(0), actor={**A, "model": None})}),
                 "human.provider": block_with(**{"CTB-1": entry(t(0), actor={**H, "provider": None})})}
        for name, block in cases.items():
            with self.subTest(field=name):
                self.assertEqual("malformed", self.verdict(block))

    def test_trailing_newline_is_never_an_exact_match(self):
        cases = [block_with(**{"EXE-1\n": entry(t(0))}),
                 block_with(**{"EXE-1": entry(t(0), ops=("modified\n",))}),
                 block_with(**{"CTB-1": entry(t(0), actor={"kind": "human\n", "id": "kevin"})}),
                 {"schema": "praxis.provenance/1\n", "contributions": {}},
                 {"schema": "praxis.provenance/2\n", "contributions": {}},
                 block_with(**{"EXE-1": entry(t(0) + "\n")})]
        for block in cases:
            with self.subTest(block=json.dumps(block)[:60]):
                self.assertEqual("malformed", self.verdict(block))

    def assertRefused(self, block, key, contribution):
        result = cp.append_contribution(block, key, contribution)
        self.assertFalse(result["ok"], result.get("block"))
        return result["error"]

    def test_append_refuses_credential_in_incoming_contribution(self):
        created = block_with(**{"EXE-1": entry(t(0), ops=("created",))})
        error = self.assertRefused(created, "EXE-2", entry(t(5), actor=B, reason="token ghp_" + "a" * 30))
        self.assertIn("credential-like", error); self.assertNotIn("ghp_", error)
        self.assertIn("credential-like", self.assertRefused(created, "EXE-2", entry(t(5), actor=B, **{"x-auth": "Bearer " + "b" * 24})))

    def test_append_refuses_contribution_dated_before_creation(self):
        created = block_with(**{"EXE-1": entry(t(10), ops=("created",))})
        self.assertRefused(created, "EXE-2", entry(t(5), actor=B))

    def test_append_refuses_created_merged_into_non_creator_with_earlier_history(self):
        history = block_with(**{"EXE-1": entry(t(0), actor=A), "EXE-2": entry(t(5), actor=B)})
        self.assertRefused(history, "EXE-2", entry(t(6), actor=B, ops=("created",)))
        with_origin = block_with(**{"EXE-1": entry(t(0), actor=A, ops=("created",)), "EXE-2": entry(t(5), actor=B)})
        self.assertRefused(with_origin, "EXE-2", entry(t(6), actor=B, ops=("created",)))

    def test_append_refuses_unknown_actor_extending_known_entry(self):
        known = block_with(**{"EXE-1": entry(t(0), actor=A, ops=("created",))})
        self.assertRefused(known, "EXE-1", entry(t(5), actor={**A, "id": "unknown"}))
        ctb = block_with(**{"CTB-1": entry(t(0), actor=H, ops=("reviewed",))})
        self.assertRefused(ctb, "CTB-1", entry(t(5), actor={"kind": "unknown", "id": "unknown"}, ops=("reviewed",)))

    def test_merge_keeps_incoming_unknown_fields_and_existing_wins(self):
        block = block_with(**{"EXE-1": entry(t(0), ops=("created",), **{"x-a": "existing"})})
        merged = ok(cp.append_contribution(block, "EXE-1", entry(t(5), **{"x-a": "incoming", "x-b": "new"})))["contributions"]["EXE-1"]
        self.assertEqual(("existing", "new"), (merged["x-a"], merged["x-b"]))
        self.assertEqual([], cp.preservation_violations(block, {**block, "contributions": {"EXE-1": merged}}))

    def test_merge_last_is_later_of_existing_and_incoming_last(self):
        block = block_with(**{"EXE-1": entry(t(0), ops=("created",), last=t(20))})
        kept = ok(cp.append_contribution(block, "EXE-1", entry(t(5), last=t(10))))["contributions"]["EXE-1"]
        self.assertEqual(t(20), kept["last"])
        advanced = ok(cp.append_contribution(block, "EXE-1", entry(t(5), last=t(30))))["contributions"]["EXE-1"]
        self.assertEqual(t(30), advanced["last"])

    def test_every_successful_append_classifies_supported(self):
        for case in (c for c in CASES if c["expect"] == "supported"):
            for key, contribution in (("EXE-20990101T000000000Z-zz", entry("2099-01-01T00:00:00.000Z", actor=B)),
                                      ("CTB-late", entry("2099-01-01T00:00:00.000Z", actor=H, ops=("reviewed",)))):
                result = cp.append_contribution(case["block"], key, contribution)
                if result["ok"]:
                    with self.subTest(case=case["name"], key=key):
                        self.assertEqual("supported", cp.classify(result["block"])["verdict"])


class EchelonChainTests(unittest.TestCase):
    def replay(self):
        records = {}
        for step in CHAIN["steps"]:
            current = records.get(step["record"], cp.empty_block())
            if "lineage" in step:
                records[step["record"]] = cp.add_lineage(current, step["lineage"]); continue
            result = cp.append_contribution(current, step["append"]["key"], step["append"]["contribution"])
            self.assertTrue(result["ok"], result.get("error"))
            self.assertEqual([], cp.preservation_violations(current, result["block"]))
            records[step["record"]] = result["block"]
        return records

    def test_each_record_keeps_its_originator(self):
        records = self.replay()
        for record, expected in CHAIN["expect"]["originators"].items():
            origin = cp.originator(records[record])
            self.assertEqual((expected["key"], expected["actorId"]), (origin["key"], origin["actor"]["id"]))

    def test_discoverer_remediator_validator_reviewer_stay_distinct(self):
        records = self.replay()
        for record, roles in CHAIN["expect"]["roles"].items():
            for role, keys in roles.items():
                self.assertEqual(keys, [x["key"] for x in cp.with_role(records[record], role)], f"{record} {role}")
        finding = records["aegis:finding/SF-0001"]
        ids = {cp.with_role(finding, r)[0]["actor"]["id"] for r in ("discovered", "remediated", "validated")}
        self.assertEqual(3, len(ids))

    def test_lineage_reconstructs_chain_without_merging_authors(self):
        records = self.replay()
        def walk(ref, seen):
            if ref in seen or ref not in records: return seen
            seen = seen | {ref}
            for nxt in records[ref].get("derivedFrom", []): seen = walk(nxt, seen)
            return seen
        reached = walk(CHAIN["expect"]["lineageFrom"], frozenset())
        for ref in CHAIN["expect"]["lineageReaches"]: self.assertIn(ref, reached)
        self.assertEqual(CHAIN["expect"]["chainOriginatorCount"], len({cp.originator(records[r])["key"] for r in reached}))

    def test_distinct_executions_of_one_agent(self):
        records = self.replay()
        expected = CHAIN["expect"]["distinctExecutionsOfOneAgent"]
        keys = sorted({k for block in records.values() for k, e in block["contributions"].items() if e["actor"]["id"] == expected["actorId"]})
        self.assertEqual(expected["keys"], keys)


class TutelaBoundaryTests(unittest.TestCase):
    def aegis_block(self):
        """The shape Aegis emits on its tutela/evidence/v1 projection: discoverer, remediator, validator, reviewer."""
        block = ok(cp.append_contribution(cp.empty_block(), "EXE-20260926T090000000Z-c1c1c1c1", {"operations": ["created", "discovered"], "at": "2026-09-26T09:00:00.000Z", "actor": B}))
        block = ok(cp.append_contribution(block, "EXE-20260926T100000000Z-a2a2a2a2", {"operations": ["remediated"], "at": "2026-09-26T10:00:00.000Z", "actor": A}))
        block = ok(cp.append_contribution(block, "EXT-github-actions.run-777-1", {"operations": ["validated"], "at": "2026-09-26T10:20:00.000Z", "actor": CI, "evidence": ["SEC-EVD-001"]}))
        block = ok(cp.append_contribution(block, "CTB-20260926-5f2e19aa", {"operations": ["reviewed"], "at": "2026-09-26T11:00:00.000Z", "actor": H}))
        block = ok(cp.append_contribution(block, "EXT-aegis.op-9", {"operations": ["transformed"], "at": "2026-09-26T11:05:00.000Z", "actor": AEGIS}))
        return cp.add_lineage(block, ["aegis:finding/SF-0001"])

    def test_supported_block_is_attached_verbatim(self):
        block = {**self.aegis_block(), "x-future": {"kept": True}}
        record = cp.attach({"id": "SEC-EVD-1", "type": "Aegis"}, block)
        self.assertEqual(block, record["contributionProvenance"])
        self.assertEqual("supported", cp.read(record)["verdict"])
        self.assertEqual([], cp.record_problems(record))

    def test_attach_never_mutates_inputs(self):
        block = self.aegis_block(); record = {"id": "E"}
        before = (json.dumps(block, sort_keys=True), json.dumps(record, sort_keys=True))
        cp.attach(record, block)
        self.assertEqual(before, (json.dumps(block, sort_keys=True), json.dumps(record, sort_keys=True)))

    def test_actor_kinds_human_agent_automation_unknown_are_carried(self):
        block = self.aegis_block()
        block = ok(cp.append_contribution(block, "CTB-unknown-1", {"operations": ["reviewed"], "at": "2026-09-26T12:00:00.000Z", "actor": U}))
        kinds = {e["actor"]["kind"] for e in cp.attach({}, block)["contributionProvenance"]["contributions"].values()}
        self.assertEqual({"agent", "human", "automation", "unknown"}, kinds)

    def test_unsupported_major_is_carried_verbatim_not_interpreted(self):
        future = {"schema": "praxis.provenance/2", "entries": [{"who": "someone"}]}
        record = cp.attach({"id": "E"}, future)
        self.assertEqual(future, record["contributionProvenance"])
        self.assertEqual("unsupported", cp.read(record)["verdict"])
        self.assertEqual([], cp.preservation_violations(future, record["contributionProvenance"]))

    def test_malformed_block_is_rejected_not_repaired(self):
        for case in (c for c in CASES if c["expect"] == "malformed"):
            with self.subTest(case=case["name"]):
                with self.assertRaises(cp.ContributionProvenanceError):
                    cp.attach({"id": "E"}, case["block"])
                self.assertTrue(cp.record_problems({"id": "E", "contributionProvenance": case["block"]}))

    def test_credentials_are_never_carried(self):
        block = self.aegis_block()
        block["contributions"]["CTB-20260926-5f2e19aa"]["reason"] = "used token ghp_" + "a" * 30
        with self.assertRaises(cp.ContributionProvenanceError) as raised:
            cp.attach({}, block)
        self.assertIn("credential-like", str(raised.exception))
        self.assertNotIn("ghp_", str(raised.exception))

    def test_legacy_record_without_block_reads_unattributed(self):
        legacy = json.loads((ROOT / "examples" / "security-assessment.json").read_text())
        self.assertEqual("unattributed", cp.read(legacy)["verdict"])
        self.assertEqual("unattributed", cp.read(legacy["evidence"][0])["verdict"])
        self.assertEqual([], cp.assessment_problems(legacy))

    def test_assessment_problems_cover_embedded_evidence(self):
        a = json.loads((ROOT / "examples" / "security-assessment.json").read_text())
        a["evidence"][0]["contributionProvenance"] = {"contributions": []}
        self.assertEqual(1, len(cp.assessment_problems(a)))
        self.assertIn("SEC-EVD-001", cp.assessment_problems(a)[0])

    def test_round_trip_through_serializer(self):
        record = cp.attach({"id": "E"}, self.aegis_block())
        again = json.loads(json.dumps(record))
        self.assertEqual(record, again)
        self.assertEqual([], cp.preservation_violations(record["contributionProvenance"], again["contributionProvenance"]))

    def test_block_is_praxis_compatible_on_the_way_out(self):
        exported = cp.attach({}, self.aegis_block())["contributionProvenance"]
        self.assertEqual("praxis.provenance/1", exported["schema"])
        self.assertEqual("supported", cp.classify(exported)["verdict"])


class EvidenceBuilderTests(unittest.TestCase):
    def test_build_without_block_is_unchanged_legacy_shape(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "a.txt"; f.write_bytes(b"x")
            self.assertNotIn("contributionProvenance", build(evidence_args(f)))

    def test_build_attaches_block_without_touching_identity_or_attestation(self):
        block = TutelaBoundaryTests().aegis_block()
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "a.txt"; f.write_bytes(b"x")
            plain = build(evidence_args(f))
            carried = build(evidence_args(f, contribution_provenance_block=block))
            self.assertEqual(block, carried["contributionProvenance"])
            self.assertEqual(plain, {k: v for k, v in carried.items() if k != "contributionProvenance"})

    def run_cli(self, block_text, out):
        with tempfile.TemporaryDirectory() as d:
            artifact = Path(d) / "a.txt"; artifact.write_bytes(b"x")
            src = Path(d) / "block.json"; src.write_text(block_text)
            return subprocess.run([sys.executable, str(ROOT / "src" / "tutela_evidence.py"), str(artifact), "--id", "SEC-EVD-1",
                                   "--source", "s", "--subject-ref", "abc", "--producer", "p", "--producer-identity-type", "workflow",
                                   "--producer-identity-value", "v", "--provenance-kind", "ci", "--provenance-issuer", "github-actions",
                                   "--run-ref", "r", "--contribution-provenance", str(src), "--output", str(out)],
                                  capture_output=True, text=True)

    def test_cli_writes_valid_block(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "e.json"
            result = self.run_cli(json.dumps(TutelaBoundaryTests().aegis_block()), out)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("supported", cp.read(json.loads(out.read_text()))["verdict"])

    def test_cli_rejects_malformed_block_before_writing(self):
        malformed = next(c for c in CASES if c["name"] == "credential-in-actor")["block"]
        for text in (json.dumps(malformed), "{not json"):
            with self.subTest(text=text[:20]), tempfile.TemporaryDirectory() as d:
                out = Path(d) / "e.json"
                result = self.run_cli(text, out)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("contributionProvenance", result.stderr)
                self.assertFalse(out.exists())

    def test_cli_reports_calendar_invalid_timestamps_without_a_traceback(self):
        for at in ("0000-01-01T00:00:00.000Z", "2026-02-30T00:00:00.000Z", "2026-09-26T24:00:00.000Z"):
            block = {"schema": "praxis.provenance/1", "contributions": {"EXE-1": {"operations": ["created"], "at": at, "actor": A}}}
            with self.subTest(at=at), tempfile.TemporaryDirectory() as d:
                out = Path(d) / "e.json"
                result = self.run_cli(json.dumps(block), out)
                self.assertEqual(2, result.returncode)
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn("calendar-valid", result.stderr)
                self.assertFalse(out.exists())

    def test_cli_carries_unsupported_major_verbatim_with_warning(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "e.json"
            future = {"schema": "praxis.provenance/3", "anything": [1, 2]}
            result = self.run_cli(json.dumps(future), out)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("carried verbatim", result.stderr)
            self.assertEqual(future, json.loads(out.read_text())["contributionProvenance"])


if __name__ == "__main__": unittest.main()
