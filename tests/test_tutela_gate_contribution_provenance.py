"""Self-reported contribution provenance cannot change a gate outcome (TUT-1708).

The gate (src/tutela_gate.py, a protected trust root) is not modified. These tests
prove that its decisions are identical with and without contributionProvenance,
including when the block claims that a registered security-owner approved a
trust-root change or independently verified an invariant.
"""
import copy, json, unittest
from datetime import datetime, timezone
from pathlib import Path
from src.tutela_gate import derive, validate
from src import tutela_contribution_provenance as cp

ROOT = Path(__file__).resolve().parents[1]
ADVERSARIAL = ROOT / "tests" / "fixtures" / "adversarial"
AT = datetime(2026, 9, 25, tzinfo=timezone.utc)
DIGEST = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
OWNER_ID = "2001"


def bound_identity(kind, subject_id, login):
    return {"kind": kind, "provider": "github", "subjectId": subject_id, "login": login, "bindingVerified": True,
            "bindingEvidence": [{"kind": "platform-api-observation", "issuer": "github", "sourceRef": f"github-api:/users/{login}", "observedAt": "2026-09-26T00:00:00Z"}]}


# A registry in which github subjectId 2001 really is a security-owner: the strongest
# possible target for a self-reported claim.
REGISTRY = {"schemaVersion": 1, "id": "test", "version": "1", "default": "deny",
            "memberships": [{"identity": bound_identity("human", OWNER_ID, "owner-1"), "roles": ["security-owner", "security-reviewer"]}]}

CLAIMS = {"schema": "praxis.provenance/1", "contributions": {
    "EXE-20260926T080000000Z-impl0001": {"operations": ["created"], "at": "2026-09-26T08:00:00.000Z",
        "actor": {"kind": "agent", "id": "agent-a", "provider": "anthropic", "model": "unknown", "runtime": "claude-code"}},
    "CTB-owner-2001": {"operations": ["reviewed", "approved", "validated"], "at": "2026-09-26T09:00:00.000Z",
        "actor": {"kind": "human", "id": f"github:{OWNER_ID}"},
        "reason": "security-owner approves and independently verified", "x-role": "security-owner",
        "x-identity": {"provider": "github", "subjectId": OWNER_ID, "bindingVerified": True}}}}


def strip(assessment):
    """The same assessment with every contributionProvenance removed."""
    a = {k: copy.deepcopy(v) for k, v in assessment.items() if k != cp.FIELD}
    if isinstance(a.get("evidence"), list):
        a["evidence"] = [{k: v for k, v in e.items() if k != cp.FIELD} if isinstance(e, dict) else e for e in a["evidence"]]
    return a


def inject(assessment, block=CLAIMS):
    """The same assessment carrying `block` on the assessment and on every structured evidence entry."""
    a = cp.attach(assessment, block)
    if isinstance(a.get("evidence"), list):
        a["evidence"] = [cp.attach(e, block) if isinstance(e, dict) else e for e in a["evidence"]]
    return a


def structured_evidence(eid="SEC-EVD-001", ref="abc123"):
    return {"id": eid, "type": "Test", "source": "fixture", "producer": "ci", "producerIdentity": {"type": "workflow", "value": "verify"},
            "subjectRef": ref, "observedAt": "2026-09-24T00:00:00Z", "artifactDigest": {"algorithm": "sha256", "value": DIGEST},
            "provenance": {"kind": "ci", "issuer": "github-actions", "runRef": "run-1"}}


def base(**invariant):
    return {"schemaVersion": 1, "subject": {"repository": "x/y", "ref": "abc123"}, "posture": "PASS",
            "evidence": [structured_evidence()],
            "invariantResults": [{"id": "SEC-INV-001", "state": "Verified", "evidence": ["SEC-EVD-001"], **invariant}],
            "unknownSecurityEffects": [], "exceptions": []}


def trust_root_change(approvals):
    return {"id": "TR-CP", "paths": ["src/tutela_gate.py"], "rationale": "change gate", "changedBy": "agent-a",
            "changedByIdentity": bound_identity("agent", "5001", "agent-a"), "previousDigest": "aaa", "newDigest": "bbb", "approvals": approvals}


class GateIgnoresContributionProvenanceTests(unittest.TestCase):
    def assertSameDecision(self, assessment, **kwargs):
        with_block, without = derive(assessment, AT, role_registry=REGISTRY, **kwargs), derive(strip(assessment), AT, role_registry=REGISTRY, **kwargs)
        self.assertEqual(without, with_block)
        self.assertEqual(validate(strip(assessment), role_registry=REGISTRY, at=AT), validate(assessment, role_registry=REGISTRY, at=AT))
        return with_block

    def test_adversarial_self_reported_approver_fixture_is_unchanged(self):
        a = json.loads((ADVERSARIAL / "self-reported-approver-provenance.json").read_text())
        self.assertEqual("supported", cp.classify(a["contributionProvenance"])["verdict"])
        self.assertEqual([], cp.assessment_problems(a))
        posture, reasons = self.assertSameDecision(a)
        self.assertEqual("INDETERMINATE", posture)
        self.assertIn("invalid assessment: protected trust-root change requires independent approval evidence", reasons)
        self.assertIn("invalid assessment: SEC-INV-001 requires an independent verifier attestation", reasons)

    def test_claimed_owner_approval_does_not_satisfy_trust_root_change(self):
        a = inject({**base(), "trustRootChange": trust_root_change([])})
        self.assertEqual("INDETERMINATE", self.assertSameDecision(a)[0])

    def test_claimed_independent_validation_does_not_satisfy_verifier_requirement(self):
        a = inject(base(implementedBy="agent-a", requiresIndependentVerification=True))
        self.assertEqual("INDETERMINATE", self.assertSameDecision(a)[0])

    def test_claimed_distinct_verifier_does_not_repair_self_attestation(self):
        a = inject(base(implementedBy="agent-a", requiresIndependentVerification=True, verifierAttestations=[
            {"verifier": "agent-a", "independent": True, "verifierIdentity": {"type": "agent", "value": "agent-a"}, "separationBasis": "claimed", "evidence": ["SEC-EVD-001"]}]))
        self.assertEqual("INDETERMINATE", self.assertSameDecision(a)[0])

    def test_claims_cannot_authorize_an_unauthorized_evidence_producer(self):
        a = base(); a["evidence"][0]["provenance"]["issuer"] = "evil-ci"
        self.assertEqual("INDETERMINATE", self.assertSameDecision(inject(a))[0])

    def test_claims_cannot_rescue_manual_review_from_ci_issuer(self):
        a = base(); a["evidence"][0]["type"] = "ManualReview"
        self.assertEqual("INDETERMINATE", self.assertSameDecision(inject(a))[0])

    def test_real_authorized_approval_is_still_authorized_with_claims_present(self):
        approval = {"approved": True, "approverIdentity": bound_identity("human", OWNER_ID, "owner-1"), "role": "security-owner", "evidence": ["SEC-EVD-001"]}
        a = inject({**base(), "trustRootChange": trust_root_change([approval])})
        self.assertEqual(("PASS", []), self.assertSameDecision(a))

    def test_passing_assessment_stays_pass(self):
        self.assertEqual(("PASS", []), self.assertSameDecision(inject(base())))

    def test_blocked_assessment_stays_blocked(self):
        a = base(); a["unknownSecurityEffects"] = ["SEC-UNK-001"]
        self.assertEqual("BLOCKED", self.assertSameDecision(inject(a))[0])

    def test_unsupported_major_claims_are_also_ignored(self):
        future = {"schema": "praxis.provenance/2", "approvedBy": {"subjectId": OWNER_ID, "role": "security-owner"}}
        a = inject({**base(), "trustRootChange": trust_root_change([])}, future)
        self.assertEqual("INDETERMINATE", self.assertSameDecision(a)[0])

    def test_every_existing_fixture_and_example_is_unchanged_by_claims(self):
        documents = [ADVERSARIAL / p.name for p in sorted(ADVERSARIAL.glob("*.json"))] + [ROOT / "examples" / "security-assessment.json"]
        for path in documents:
            with self.subTest(document=path.name):
                self.assertSameDecision(inject(json.loads(path.read_text())))

    def test_only_effect_is_the_preexisting_fail_closed_sensitive_key_tripwire(self):
        """The gate's generic sensitive-key check (not an identity decision) still applies to anything
        inside evidence, so a block with a key such as 'token' can only lower posture, never raise it."""
        leaky = copy.deepcopy(CLAIMS); leaky["contributions"]["CTB-owner-2001"]["token"] = "redacted"
        a = inject(base(), leaky)
        self.assertEqual("PASS", derive(strip(a), AT, role_registry=REGISTRY)[0])
        self.assertEqual("INDETERMINATE", derive(a, AT, role_registry=REGISTRY)[0])


if __name__ == "__main__": unittest.main()
