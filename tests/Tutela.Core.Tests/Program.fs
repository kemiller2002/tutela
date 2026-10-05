/// Tutela.Core tests. A dependency-free harness: every check is recorded, a
/// summary with counts is printed at the end, and any failure exits 1.
module Tutela.Core.Tests.Program

open System
open System.IO
open Tutela.Core

// ---------------------------------------------------------------- harness

type Check = { Name: string; Passed: bool; Detail: string }

let check name passed detail = { Name = name; Passed = passed; Detail = detail }
let equal name expected actual = check name (expected = actual) $"expected %A{expected}, got %A{actual}"
let isTrue name condition = check name condition "expected true"

let repoRoot =
    let rec up (dir: DirectoryInfo) =
        if isNull dir then failwith "repository root (Tutela.sln) not found"
        elif File.Exists(Path.Combine(dir.FullName, "Tutela.sln")) then dir.FullName
        else up dir.Parent
    up (DirectoryInfo AppContext.BaseDirectory)

let readRepo (rel: string) = File.ReadAllText(Path.Combine(repoRoot, rel))
let jsonRepo rel = Json.parse (readRepo rel) |> Result.defaultWith failwith
let ok r = r |> Result.defaultWith (fun e -> failwith $"%A{e}")

let at = DateTimeOffset(2026, 9, 25, 0, 0, 0, TimeSpan.Zero)

// ---------------------------------------------------------------- fixtures

let iid x = InvariantId.create x |> ok
let eid x = EvidenceId.create x |> ok
let invariant state evidence = { Id = iid "SEC-INV-001"; State = state; Evidence = evidence; ContradictoryEvidence = [] }
let assessment state evidence unknown exceptions =
    { Invariants = [ invariant state evidence ]; UnknownSecurityEffects = unknown; Exceptions = exceptions }

let github kind id login = PlatformIdentity.github kind id (Some login) |> ok
let owner = github Human 2001UL "owner-1"
let author = github Agent 5001UL "author"
let registryWith memberships = RoleRegistry.create "deny" memberships
let ownerRegistry = registryWith [ { Identity = owner; Roles = Set.ofList [ SecurityOwner ]; ValidFrom = None; ValidUntil = None } ]
let emptyRegistry = registryWith []

let honoredException =
    { Id = "SEC-EXC-001"
      Approved = true
      CreatedAt = Some (at.AddDays -5.0)
      ExpiresAt = Some (at.AddDays 30.0)
      Covers = [ "SEC-INV-001" ]
      Rationale = Some "temporary acceptance"
      CompensatingControls = [ "feature disabled" ]
      Evidence = [ "SEC-EVD-001" ]
      RequestedBy = Some author
      ApproverIdentity = Some owner }

let posture registry a = (Gate.derive at registry a).Posture

// ---------------------------------------------------------------- typed gate

let latticeChecks =
    [ equal "pass" Pass (posture emptyRegistry (assessment Verified [ eid "E1" ] [] []))
      equal "violation" Blocked (posture emptyRegistry (assessment Violated [ eid "E1" ] [] []))
      equal "unknown-effect" Blocked (posture emptyRegistry (assessment Verified [ eid "E1" ] [ "SEC-UNK-001" ] []))
      equal "unknown" Indeterminate (posture emptyRegistry (assessment Unknown [ eid "E1" ] [] []))
      equal "stale" Indeterminate (posture emptyRegistry (assessment Stale [ eid "E1" ] [] []))
      equal "missing-evidence" Indeterminate (posture emptyRegistry (assessment Verified [] [] [])) ]

// TUT-1103, TUT-1104, TUT-1105, TUT-1204, TUT-0006: exception approval.
let exceptionChecks =
    let violated e = assessment Violated [ eid "E1" ] [] [ e ]
    let rejections registry e = ExceptionApproval.rejections at registry e
    let ownerWith roles validUntil = registryWith [ { Identity = owner; Roles = Set.ofList roles; ValidFrom = None; ValidUntil = validUntil } ]
    let bot = github Agent 2001UL "owner-bot"
    [ equal "exception-honored-conditional" Conditional (posture ownerRegistry (violated honoredException))
      equal "exception-honored-no-rejections" [] (rejections ownerRegistry honoredException)
      equal "exception-self-approval-blocks" Blocked (posture ownerRegistry (violated { honoredException with RequestedBy = Some owner }))
      equal "exception-self-approval-code" [ SelfApproval ] (rejections ownerRegistry { honoredException with RequestedBy = Some owner })
      equal "exception-renamed-login-is-still-self" [ SelfApproval ]
          (rejections ownerRegistry { honoredException with RequestedBy = Some (github Human 2001UL "owner-renamed") })
      equal "exception-approver-not-in-registry" [ ApproverLacksRole ] (rejections emptyRegistry honoredException)
      equal "exception-same-login-other-subject" [ ApproverLacksRole ]
          (rejections ownerRegistry { honoredException with ApproverIdentity = Some (github Human 9999UL "owner-1") })
      equal "exception-reviewer-role-insufficient" [ ApproverLacksRole ] (rejections (ownerWith [ SecurityReviewer ] None) honoredException)
      equal "exception-agent-approver" [ ApproverNotHuman ]
          (rejections (registryWith [ { Identity = bot; Roles = Set.ofList [ SecurityOwner ]; ValidFrom = None; ValidUntil = None } ])
              { honoredException with ApproverIdentity = Some bot })
      equal "exception-expired-membership" [ ApproverLacksRole ] (rejections (ownerWith [ SecurityOwner ] (Some (at.AddDays -1.0))) honoredException)
      equal "exception-expired" [ Expired ] (rejections ownerRegistry { honoredException with ExpiresAt = Some (at.AddDays -1.0) })
      equal "exception-expired-blocks" Blocked (posture ownerRegistry (violated { honoredException with ExpiresAt = Some (at.AddDays -1.0) }))
      equal "exception-expires-at-instant" [ Expired ] (rejections ownerRegistry { honoredException with ExpiresAt = Some at })
      equal "exception-missing-expiry" [ InvalidExpiry ] (rejections ownerRegistry { honoredException with ExpiresAt = None })
      equal "exception-not-yet-valid" [ NotYetValid ] (rejections ownerRegistry { honoredException with CreatedAt = Some (at.AddDays 1.0) })
      equal "exception-not-approved" [ NotApproved ] (rejections ownerRegistry { honoredException with Approved = false })
      equal "exception-unbound-requester" [ RequesterUnbound ] (rejections ownerRegistry { honoredException with RequestedBy = None })
      equal "exception-unbound-approver" [ ApproverUnbound ] (rejections ownerRegistry { honoredException with ApproverIdentity = None })
      equal "exception-incomplete" [ IncompleteRecord ] (rejections ownerRegistry { honoredException with CompensatingControls = [] })
      equal "exception-permissive-registry" [ ApproverLacksRole ] (rejections (RoleRegistry.create "allow" []) honoredException) ]

let domainChecks =
    let sha256 = String.replicate 64 "a"
    let aliceOld = github Human 12345UL "alice"
    let aliceRenamed = github Human 12345UL "alice-new"
    let impostor = github Human 54321UL "alice"
    let membership = { Identity = aliceOld; Roles = Set.ofList [ SecurityOwner ]; ValidFrom = None; ValidUntil = None }
    let registry = RoleRegistry.create "deny" [ membership ] |> ok
    [ isTrue "sha256-digest-valid" (ArtifactDigest.create Sha256 sha256 |> Result.isOk)
      isTrue "sha256-digest-short-rejected" (ArtifactDigest.create Sha256 "aaa" |> Result.isError)
      isTrue "sha512-needs-128" (ArtifactDigest.create Sha512 sha256 |> Result.isError)
      isTrue "rename-preserves-subject" (PlatformIdentity.sameSubject aliceOld aliceRenamed)
      equal "login-cannot-confer-authority" false (PlatformIdentity.sameSubject aliceOld impostor)
      equal "matching-subject-role" (Set.ofList [ SecurityOwner ]) (RoleRegistry.rolesAt at aliceRenamed registry)
      equal "same-login-different-subject-no-role" Set.empty (RoleRegistry.rolesAt at impostor registry)
      isTrue "permissive-role-registry-rejected" (RoleRegistry.create "allow" [] |> Result.isError)
      isTrue "naive-time-rejected" (Time.parse "2099-01-01T00:00:00" |> Result.isError)
      isTrue "offset-time-accepted" (Time.parse "2099-01-01T00:00:00Z" |> Result.isOk) ]

// ---------------------------------------------------------------- parity corpus

let samples =
    Map.ofList [ "aws-access-key-id", "AKIA" + "ABCDEFGHIJKLMNOP"; "pem-private-key", "-----BEGIN " + "RSA PRIVATE KEY-----" ]

let rec expand value =
    match value with
    | JString s -> JString (samples |> Map.fold (fun (acc: string) name sample -> acc.Replace($"<<sample:{name}>>", sample)) s)
    | JArray xs -> JArray (List.map expand xs)
    | JObject ms -> JObject (ms |> List.map (fun (k, v) -> k, expand v))
    | v -> v

let defaultPolicy () =
    { Authority = AuthorityPolicyDocument.parse (jsonRepo "security/PROVENANCE-AUTHORITY.json")
      TrustRoot = TrustRootPolicyDocument.parse (jsonRepo "security/TRUST-ROOT-CHANGE.json")
      Roles = RoleRegistryDocument.parse (jsonRepo "security/ROLE-REGISTRY.json")
      Sensitive = SensitiveData.parse (jsonRepo "security/SENSITIVE-DATA-RULES.json") |> ok }

// TUT-1804, TUT-1807: the F# authority reproduces the oracle exactly.
let parityChecks =
    let corpus = jsonRepo "tests/parity/corpus.json"
    let basePolicy = defaultPolicy ()
    let cases = Json.getOr "cases" (JArray []) corpus |> Json.items
    let perCase =
        cases
        |> List.collect (fun c ->
            let name = Json.stringOf "name" c |> Option.defaultValue "?"
            let caseAt = Json.stringOf "at" c |> Option.get |> Time.parse |> ok
            let document =
                match Json.stringOf "assessmentPath" c with
                | Some path -> jsonRepo path
                | None -> Json.getOr "assessment" JNull c |> expand
            let policy =
                { basePolicy with
                    Roles = Json.get "roleRegistry" c |> Option.map RoleRegistryDocument.parse |> Option.defaultValue basePolicy.Roles
                    Authority = Json.get "authorityPolicy" c |> Option.map AuthorityPolicyDocument.parse |> Option.defaultValue basePolicy.Authority }
            let evaluation = Gate.evaluate caseAt policy document
            let expect = Json.getOr "expect" JNull c
            [ equal $"parity/{name}/posture" (Json.stringOf "posture" expect) (Some (Verification.postureText evaluation.Derivation.Posture))
              equal $"parity/{name}/reasons" (Json.strings "reasons" expect) evaluation.Derivation.Reasons
              match Json.get "exceptionRejections" c with
              | Some expected ->
                  let first = Json.getOr "exceptions" (JArray []) document |> Json.items |> List.head |> Gate.projectException
                  let actual = ExceptionApproval.rejections caseAt policy.Roles first |> List.map ExceptionRejection.code
                  equal $"parity/{name}/rejections" (Json.items expected |> List.choose Json.tryString) actual
              | None -> () ])
    isTrue "parity-corpus-size" (cases.Length >= 80) :: perCase

// ---------------------------------------------------------------- sensitive data / secret scan (TUT-0401)

let scanChecks =
    let catalog = SensitiveData.parse (jsonRepo "security/SENSITIVE-DATA-RULES.json") |> ok
    let ghToken = "gh" + "p_" + String.replicate 36 "A"
    let jwt = "eyJ" + String.replicate 12 "a" + "." + String.replicate 12 "b" + "." + String.replicate 12 "c"
    let text = $"line one\nconfig = \"{ghToken}\"\nok\n{jwt}\n"
    let findings = SensitiveData.scanText catalog "sample.txt" text
    [ equal "scan-finds-credentials-by-line" [ "TUTELA-SD-V001", 2; "TUTELA-SD-V008", 4 ] (findings |> List.map (fun f -> f.RuleId, f.Line))
      equal "scan-lookalikes-clean" [] (SensitiveData.scanText catalog "doc.md" "task-description-for-the-risk-assessment-team and tokenizer")
      equal "scan-binary-skipped" [] (SensitiveData.scanText catalog "blob.bin" (ghToken + "\000"))
      equal "catalog-key-ids"
          [ "TUTELA-SD-K001"; "TUTELA-SD-K002"; "TUTELA-SD-K003"; "TUTELA-SD-K004"; "TUTELA-SD-K005"; "TUTELA-SD-K006"; "TUTELA-SD-K007" ]
          (catalog.KeyRules |> List.map _.Id)
      equal "catalog-key-case-insensitive" (Some (SensitiveKey "TUTELA-SD-K004")) (SensitiveData.find catalog (JObject [ "API-Key", JString "x" ]))
      isTrue "catalog-empty-rejected" (SensitiveData.parse (JObject [ "schema", JString SensitiveData.Schema ]) |> Result.isError)
      isTrue "catalog-wrong-schema-rejected" (SensitiveData.parse (JObject []) |> Result.isError) ]

// ---------------------------------------------------------------- contract

let contractChecks =
    let policy = defaultPolicy ()
    let example = jsonRepo "examples/security-assessment.json"
    let evaluation = Gate.evaluate at policy example
    let result =
        Verification.ofEvaluation at "test" (Some "examples/security-assessment.json") None (Some ("example/app", "0123456789abcdef")) (Some "BLOCKED") [] evaluation
    let json = Verification.toJson result
    let selfApproved =
        let a = assessment Violated [ eid "E1" ] [] [ { honoredException with RequestedBy = Some owner } ]
        let derivation, decisions = Gate.deriveWithDecisions at ownerRegistry a
        { Derivation = derivation; ValidationErrors = []; ExceptionDecisions = decisions; StaleEvidence = []; Assessment = Some a }
        |> Verification.ofEvaluation at "test" None None None None []
        |> Verification.toJson
    let rejectionRuleIds =
        Json.getOr "exceptions" (JArray []) selfApproved
        |> Json.items
        |> List.collect (Json.getOr "rejections" (JArray []) >> Json.items)
        |> List.choose (Json.stringOf "ruleId")
    [ equal "contract-schema" (Some "tutela.verification/1") (Json.stringOf "schema" json)
      equal "contract-verdict-blocked" (Some "blocked") (Json.stringOf "verdict" json)
      equal "contract-declared-matches" (Some (JBool true)) (Json.get "declaredMatches" json)
      isTrue "contract-unknown-effect-finding"
          (Json.getOr "findings" (JArray []) json |> Json.items |> List.exists (fun f -> Json.stringOf "ruleId" f = Some RuleIds.UnknownSecurityEffect))
      equal "contract-self-approval-rejection" [ "TUTELA-G209" ] rejectionRuleIds
      equal "contract-self-approval-verdict" (Some "blocked") (Json.stringOf "verdict" selfApproved)
      equal "contract-exit-codes" [ 0; 0; 1; 1; 3 ]
          ([ VerdictPass; VerdictConditional; VerdictBlocked; VerdictIndeterminate; VerdictUnavailable ] |> List.map Verification.exitCode)
      equal "contract-unavailable-verdict" (Some "unavailable")
          (Verification.unavailable at "test" None "policy unreadable" |> Verification.toJson |> Json.stringOf "verdict")
      isTrue "contract-schema-file-declares-version" ((readRepo "schemas/verification-result.schema.json").Contains "tutela.verification/1") ]

// ---------------------------------------------------------------- traceability

let traceChecks =
    // Synthetic ids (TUT-90xx) so this test never counts as coverage of a real requirement.
    let requirements = "# R\nTUT-9001 MUST a.\nTUT-9002 MUST b.\nsee TUT-9003 inline\nTUT-9003 MUST c.\n"
    let ids = Traceability.requirementIds requirements
    let report = Traceability.build ids [ "tests/a.py", "covers TUT-9001" ] [ "src/x.fs", "TUT-9002 TUT-9001" ] (Some 1)
    [ equal "trace-ids" [ "TUT-9001"; "TUT-9002"; "TUT-9003" ] ids
      equal "trace-code-reference-is-not-test-coverage" [ "TUT-9002"; "TUT-9003" ] (Traceability.untested report |> List.map _.Id)
      equal "trace-ratchet-exceeded" (RatchetExceeded (1, 2)) report.Status
      equal "trace-within" WithinRatchet (Traceability.build ids [ "tests/a.py", "TUT-9001 TUT-9002 TUT-9003" ] [] (Some 0)).Status
      equal "trace-real-requirement-count" 108 (Traceability.requirementIds (readRepo "requirements/TUTELA-REQUIREMENTS.md")).Length ]

[<EntryPoint>]
let main _ =
    let checks = latticeChecks @ exceptionChecks @ domainChecks @ parityChecks @ scanChecks @ contractChecks @ traceChecks
    let failures = checks |> List.filter (fun c -> not c.Passed)
    failures |> List.iter (fun c -> eprintfn "FAIL %s: %s" c.Name c.Detail)
    printfn "Tutela.Core tests: %d checks, %d passed, %d failed" checks.Length (checks.Length - failures.Length) failures.Length
    if failures.IsEmpty then 0 else 1
