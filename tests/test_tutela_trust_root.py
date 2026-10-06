import json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from src.tutela_trust_root import protected_changes, verify

REPO=Path(__file__).resolve().parents[1]
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

def fake_digest(ref,paths):
    # Digests are bound to real git content in GitTransitionTests; here they name the ref and the paths they cover.
    return {"algorithm":"sha256","value":ref+":"+",".join(sorted(paths))}

def record(paths,approvals=(approval("security-owner"),)):
    return {"paths":list(paths),"previousDigest":fake_digest("base",paths),"newDigest":fake_digest("head",paths),"approvals":list(approvals)}

def new(rec,path="security/transitions/TR-9999-0001.json"):
    """A transition record added by the change under test."""
    return (path,"added",rec)

def check(changed,records,base_policy=POLICY,head_policy=POLICY):
    """records: None for no record, a record dict for one added record, or a list of (path, state, record)."""
    entries=[] if records is None else [new(records)] if isinstance(records,dict) else list(records)
    with patch("src.tutela_trust_root.changed_paths",return_value=changed), \
         patch("src.tutela_trust_root.load_policy",return_value=base_policy), \
         patch("src.tutela_trust_root.transition_records",return_value=entries), \
         patch("src.tutela_trust_root.transition_digest",side_effect=fake_digest):
        return verify("base","head",head_policy)

class TrustRootDiffTests(unittest.TestCase):
    def assertError(self,fragment,errors):
        self.assertTrue(any(fragment in e for e in errors),f"{fragment!r} not in {errors!r}")

    def test_unprotected_change_needs_no_record(self):
        self.assertEqual([],check(["README.md"],None))

    def test_protected_change_without_record_fails(self):
        self.assertIn("without a transition record",check(["src/gate.py"],None)[0])

    def test_record_must_cover_exact_protected_diff(self):
        self.assertError("transition paths do not exactly match protected files changed",check(["src/gate.py"],record(["src/gate.py","security/P.json"])))

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
        self.assertError("transition paths do not exactly match protected files changed",errors)

    # (b) Dropping a path from protection at all, without editing it.
    def test_dropping_path_requires_record_covering_it(self):
        errors=check([POLICY_FILE],record([POLICY_FILE]),head_policy=DROPPED)
        self.assertError("transition paths do not exactly match protected files changed",errors)

    def test_dropping_path_from_deleted_policy_without_record_fails(self):
        errors=check([POLICY_FILE],None,head_policy={})
        self.assertIn("src/gate.py",errors[0])

    def test_dropping_path_requires_security_owner_approval(self):
        rec=record([POLICY_FILE,"src/gate.py"],[approval("security-reviewer")])
        errors=check([POLICY_FILE],rec,head_policy=DROPPED)
        self.assertError("removing protected paths requires an approved security-owner transition: src/gate.py",errors)

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
        self.assertError("transition record has no approved approval from an authorized trust-root role",errors)

    def test_approval_role_must_match_identity_kind(self):
        errors=check(["src/gate.py"],record(["src/gate.py"],[approval("security-owner","agent")]))
        self.assertError("transition record has no approved approval from an authorized trust-root role",errors)

    def test_head_policy_cannot_grant_its_own_approval_authority(self):
        head={"protectedPaths":POLICY["protectedPaths"],"approvalAuthorities":AUTHORITIES+[{"id":"x","roles":["self"],"mayApprove":["trust-root-change"],"mayAuthorizeWeakening":True,"identityKinds":["agent"]}]}
        errors=check([POLICY_FILE],record([POLICY_FILE],[approval("self","agent")]),head_policy=head)
        self.assertError("transition record has no approved approval from an authorized trust-root role",errors)

    def test_protected_changes_uses_one_policy(self):
        self.assertEqual(["src/gate.py"],protected_changes(["src/gate.py","README.md"],POLICY))

    # Every transition record in the change is checked, not only the last one.
    def test_records_whose_union_covers_the_change_pass(self):
        recs=[new(record(["src/gate.py"]),"security/transitions/A.json"),new(record(["security/P.json"]),"security/transitions/B.json")]
        self.assertEqual([],check(["src/gate.py","security/P.json"],recs))

    def test_union_of_records_must_cover_every_protected_change(self):
        recs=[new(record(["src/gate.py"]),"security/transitions/A.json"),new(record(["src/gate.py"]),"security/transitions/B.json")]
        errors=check(["src/gate.py","security/P.json"],recs)
        self.assertError("not covered by any transition record: security/P.json",errors)

    def test_an_invalid_earlier_record_fails_even_when_the_last_is_valid(self):
        recs=[new(record(["src/gate.py"],[]),"security/transitions/A.json"),new(record(["src/gate.py"]),"security/transitions/B.json")]
        self.assertError("security/transitions/A.json: transition record has no approved approval from an authorized trust-root role",check(["src/gate.py"],recs))

    def test_an_invalid_later_record_fails_even_when_the_first_is_valid(self):
        bad=record(["src/gate.py"])|{"newDigest":{"algorithm":"sha256","value":"wrong"}}
        recs=[new(record(["src/gate.py"]),"security/transitions/A.json"),new(bad,"security/transitions/Z.json")]
        self.assertError("security/transitions/Z.json: transition newDigest does not match head protected content",check(["src/gate.py"],recs))

    def test_record_listing_an_unchanged_path_fails(self):
        recs=[new(record(["src/gate.py"]),"security/transitions/A.json"),new(record(["security/P.json"]),"security/transitions/B.json")]
        self.assertError("security/transitions/B.json: transition paths do not exactly match protected files changed",check(["src/gate.py"],recs))

    def test_record_added_without_any_protected_change_fails(self):
        self.assertError("transition paths do not exactly match protected files changed",check(["README.md"],record(["src/gate.py"])))

    def test_record_without_paths_fails(self):
        recs=[new(record(["src/gate.py"]),"security/transitions/A.json"),new(record([]),"security/transitions/B.json")]
        self.assertError("security/transitions/B.json: transition record lists no paths",check(["src/gate.py"],recs))

    def test_malformed_record_fails(self):
        recs=[new(record(["src/gate.py"]),"security/transitions/A.json"),new(None,"security/transitions/B.json")]
        self.assertError("security/transitions/B.json: transition record is not a JSON object",check(["src/gate.py"],recs))

    def test_removal_must_be_owner_approved_by_the_record_that_covers_it(self):
        recs=[new(record([POLICY_FILE]),"security/transitions/A.json"),
              new(record(["src/gate.py"],[approval("security-reviewer","agent")]),"security/transitions/B.json")]
        errors=check([POLICY_FILE],recs,head_policy=DROPPED)
        self.assertError("security/transitions/B.json: removing protected paths requires an approved security-owner transition: src/gate.py",errors)

    # Merged transition records are immutable history.
    def test_modifying_a_merged_record_fails(self):
        recs=[("security/transitions/TR-OLD.json","modified",record(["src/gate.py"]))]
        self.assertError("security/transitions/TR-OLD.json: transition record already exists at base and must not be changed",check(["src/gate.py"],recs))

    def test_deleting_a_merged_record_fails(self):
        recs=[("security/transitions/TR-OLD.json","deleted",None)]
        self.assertError("security/transitions/TR-OLD.json: transition record already exists at base and must not be changed",check(["README.md"],recs))

    def test_modifying_a_merged_record_fails_even_with_a_valid_new_record(self):
        recs=[("security/transitions/TR-OLD.json","modified",record(["security/P.json"])),new(record(["src/gate.py"]))]
        self.assertError("must not be changed",check(["src/gate.py"],recs))

class RepositoryPolicyTests(unittest.TestCase):
    """The enforcer of the trust-root check is itself a trust root."""
    def test_enforcing_workflow_and_checker_are_protected(self):
        policy=json.loads((REPO/POLICY_FILE).read_text())
        for path in [".github/workflows/tutela-foundation.yml","src/tutela_trust_root.py",POLICY_FILE]:
            self.assertIn(path,policy["protectedPaths"])

    def test_workflow_lets_the_checker_discover_every_record(self):
        workflow=(REPO/".github/workflows/tutela-foundation.yml").read_text()
        self.assertIn('python src/tutela_trust_root.py --base "$base" --head HEAD',workflow)
        self.assertNotIn("--record",workflow)
        self.assertNotIn("tail -n 1",workflow)

class GitTransitionTests(unittest.TestCase):
    """End to end against a real git history, through the command line CI runs."""
    def setUp(self):
        self.dir=Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree,self.dir)
        (self.dir/"src").mkdir(); (self.dir/"security"/"transitions").mkdir(parents=True)
        shutil.copy(REPO/"src"/"tutela_trust_root.py",self.dir/"src"/"tutela_trust_root.py")
        self.git("init","-q","-b","main"); self.git("config","user.email","t@example.invalid"); self.git("config","user.name","t")
        self.git("config","commit.gpgsign","false")
        self.write(POLICY_FILE,json.dumps(POLICY))
        self.write("src/gate.py","v1\n"); self.write("security/P.json","{}\n")
        self.base=self.commit("base")

    def git(self,*args):
        return subprocess.check_output(["git",*args],cwd=self.dir,text=True).strip()

    def write(self,path,text):
        (self.dir/path).write_text(text)

    def commit(self,message):
        self.git("add","-A"); self.git("commit","-q","-m",message)
        return self.git("rev-parse","HEAD")

    def digest(self,ref,paths):
        code="import json,sys;sys.path.insert(0,'src');import tutela_trust_root as t;print(json.dumps(t.transition_digest(sys.argv[1],sys.argv[2:])))"
        return json.loads(subprocess.run([sys.executable,"-c",code,ref,*paths],cwd=self.dir,capture_output=True,text=True,check=True).stdout)

    def record(self,name,paths,head,approvals=None):
        rec={"paths":paths,"previousDigest":self.digest(self.base,paths),"newDigest":self.digest(head,paths),
             "approvals":approvals if approvals is not None else [approval("security-owner")]}
        self.write(f"security/transitions/{name}.json",json.dumps(rec))

    def run_check(self):
        proc=subprocess.run([sys.executable,"src/tutela_trust_root.py","--base",self.base,"--head","HEAD"],cwd=self.dir,capture_output=True,text=True)
        return proc.returncode,json.loads(proc.stdout)["errors"]

    def edit_both(self):
        self.write("src/gate.py","v2\n"); self.write("security/P.json",'{"x":1}\n')
        return self.commit("edit")

    def test_two_records_covering_the_change_pass(self):
        head=self.edit_both()
        self.record("TR-1",["src/gate.py"],head); self.record("TR-2",["security/P.json"],head); self.commit("records")
        self.assertEqual((0,[]),self.run_check())

    def test_bad_earlier_record_is_caught_although_the_last_is_valid(self):
        head=self.edit_both()
        self.record("TR-1",["src/gate.py"],head,approvals=[]); self.record("TR-2",["security/P.json","src/gate.py"],head); self.commit("records")
        code,errors=self.run_check()
        self.assertEqual(1,code)
        self.assertTrue(any(e.startswith("security/transitions/TR-1.json:") for e in errors),errors)

    def test_change_to_merged_record_is_rejected(self):
        head=self.edit_both()
        self.record("TR-1",["security/P.json","src/gate.py"],head); self.base=self.commit("records")
        self.write("security/transitions/TR-1.json",json.dumps({"paths":[],"approvals":[]})); self.commit("tamper")
        code,errors=self.run_check()
        self.assertEqual(1,code)
        self.assertTrue(any("must not be changed" in e for e in errors),errors)

    def test_deleting_merged_record_is_rejected(self):
        head=self.edit_both()
        self.record("TR-1",["security/P.json","src/gate.py"],head); self.base=self.commit("records")
        os.remove(self.dir/"security/transitions/TR-1.json"); self.commit("delete")
        code,errors=self.run_check()
        self.assertEqual(1,code)
        self.assertTrue(any("must not be changed" in e for e in errors),errors)

if __name__=="__main__": unittest.main()
