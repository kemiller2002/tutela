import unittest
from unittest.mock import patch
from src.tutela_trust_root import protected_changes, verify

POLICY_FILE="security/TRUST-ROOT-CHANGE.json"
AUTHORITIES=[
    {"id":"security-reviewer","roles":["security-reviewer"],"mayApprove":["trust-root-change"],"mayAuthorizeWeakening":False,"identityKinds":["human","agent"]},
    {"id":"security-owner","roles":["security-owner"],"mayApprove":["trust-root-change"],"mayAuthorizeWeakening":True,"identityKinds":["human"]},
]
POLICY={"protectedPaths":[POLICY_FILE,"security/P.json","src/gate.py"],"approvalAuthorities":AUTHORITIES}
# The head policy drops src/gate.py from protection.
DROPPED={"protectedPaths":[POLICY_FILE,"security/P.json"],"approvalAuthorities":AUTHORITIES}

def approval(role,kind="human"):
    return {"approved":True,"role":role,"approverIdentity":{"kind":kind,"provider":"github","subjectId":"1"},"evidence":["x"]}

def record(paths,approvals=(approval("security-owner"),)):
    return {"paths":list(paths),"previousDigest":{"algorithm":"sha256","value":"before"},"newDigest":{"algorithm":"sha256","value":"after"},"approvals":list(approvals)}

def check(changed,rec,base_policy=POLICY,head_policy=POLICY):
    # Digests are bound to real git content elsewhere; here they always match the record.
    with patch("src.tutela_trust_root.changed_paths",return_value=changed), \
         patch("src.tutela_trust_root.load_policy",return_value=base_policy,create=True), \
         patch("src.tutela_trust_root.transition_digest",side_effect=[{"algorithm":"sha256","value":"before"},{"algorithm":"sha256","value":"after"}]):
        return verify("base","head",rec,head_policy)

class TrustRootDiffTests(unittest.TestCase):
    def test_unprotected_change_needs_no_record(self):
        self.assertEqual([],check(["README.md"],None))

    def test_protected_change_without_record_fails(self):
        self.assertIn("without a transition record",check(["src/gate.py"],None)[0])

    def test_record_must_cover_exact_protected_diff(self):
        self.assertIn("exactly match",check(["src/gate.py"],record(["src/gate.py","security/P.json"]))[0])

    def test_digests_are_bound_to_actual_base_and_head(self):
        rec=record(["src/gate.py"])|{"previousDigest":{"algorithm":"sha256","value":"wrong"},"newDigest":{"algorithm":"sha256","value":"wrong"}}
        self.assertEqual(2,len(check(["src/gate.py"],rec)))

    def test_matching_transition_passes(self):
        self.assertEqual([],check(["src/gate.py"],record(["src/gate.py"])))

    def test_security_reviewer_may_approve_a_non_removing_change(self):
        self.assertEqual([],check(["src/gate.py"],record(["src/gate.py"],[approval("security-reviewer","agent")])))

    # (a) Dropping a path from protection and editing it in the same change.
    def test_dropped_and_edited_path_without_record_fails(self):
        errors=check([POLICY_FILE,"src/gate.py"],None,head_policy=DROPPED)
        self.assertEqual(1,len(errors))
        self.assertIn("src/gate.py",errors[0])

    def test_dropped_and_edited_path_not_covered_by_record_fails(self):
        errors=check([POLICY_FILE,"src/gate.py"],record([POLICY_FILE]),head_policy=DROPPED)
        self.assertIn("transition paths do not exactly match protected files changed",errors)

    # (b) Dropping a path from protection at all, without editing it.
    def test_dropping_path_requires_record_covering_it(self):
        errors=check([POLICY_FILE],record([POLICY_FILE]),head_policy=DROPPED)
        self.assertIn("transition paths do not exactly match protected files changed",errors)

    def test_dropping_path_from_deleted_policy_without_record_fails(self):
        errors=check([POLICY_FILE],None,head_policy={})
        self.assertIn("src/gate.py",errors[0])

    def test_dropping_path_requires_security_owner_approval(self):
        rec=record([POLICY_FILE,"src/gate.py"],[approval("security-reviewer")])
        errors=check([POLICY_FILE],rec,head_policy=DROPPED)
        self.assertIn("removing protected paths requires an approved security-owner transition: src/gate.py",errors)

    def test_dropping_path_with_covering_owner_approved_record_passes(self):
        self.assertEqual([],check([POLICY_FILE],record([POLICY_FILE,"src/gate.py"]),head_policy=DROPPED))

    def test_dropped_and_edited_path_with_covering_owner_approved_record_passes(self):
        self.assertEqual([],check([POLICY_FILE,"src/gate.py"],record([POLICY_FILE,"src/gate.py"]),head_policy=DROPPED))

    # Adding a path to protection makes it protected for the change that adds it.
    def test_newly_protected_path_is_covered(self):
        head={"protectedPaths":POLICY["protectedPaths"]+["src/new.py"],"approvalAuthorities":AUTHORITIES}
        self.assertIn("src/new.py",check([POLICY_FILE,"src/new.py"],None,head_policy=head)[0])

    def test_record_without_authorized_approval_fails(self):
        errors=check(["src/gate.py"],record(["src/gate.py"],[]))
        self.assertIn("transition record has no approved approval from an authorized trust-root role",errors)

    def test_approval_role_must_match_identity_kind(self):
        errors=check(["src/gate.py"],record(["src/gate.py"],[approval("security-owner","agent")]))
        self.assertIn("transition record has no approved approval from an authorized trust-root role",errors)

    def test_head_policy_cannot_grant_its_own_approval_authority(self):
        head={"protectedPaths":POLICY["protectedPaths"],"approvalAuthorities":AUTHORITIES+[{"id":"x","roles":["self"],"mayApprove":["trust-root-change"],"mayAuthorizeWeakening":True,"identityKinds":["agent"]}]}
        errors=check([POLICY_FILE],record([POLICY_FILE],[approval("self","agent")]),head_policy=head)
        self.assertIn("transition record has no approved approval from an authorized trust-root role",errors)

    def test_protected_changes_uses_one_policy(self):
        self.assertEqual(["src/gate.py"],protected_changes(["src/gate.py","README.md"],POLICY))

if __name__=="__main__": unittest.main()
