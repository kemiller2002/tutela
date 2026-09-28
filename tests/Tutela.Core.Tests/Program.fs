open System
open Tutela.Core
open Tutela.Core.Gate

let fail message = eprintfn "%s" message; Environment.ExitCode <- 1
let assertEqual name expected actual = if expected <> actual then fail $"{name}: expected {expected}, got {actual}"
let iid x = InvariantId.create x |> Result.defaultWith failwith
let eid x = EvidenceId.create x |> Result.defaultWith failwith
let invariant state evidence = { Id=iid "SEC-INV-001"; State=state; Evidence=evidence; ContradictoryEvidence=[] }
let assessment state evidence unknown exceptions =
    { Invariants=[invariant state evidence]; UnknownSecurityEffects=Set.ofList unknown; Exceptions=exceptions }
let at = DateTimeOffset(2026,9,25,0,0,0,TimeSpan.Zero)

assertEqual "pass" Pass (derive at (assessment Verified [eid "E1"] [] [])).Posture
assertEqual "violation" Blocked (derive at (assessment Violated [eid "E1"] [] [])).Posture
assertEqual "unknown-effect" Blocked (derive at (assessment Verified [eid "E1"] ["SEC-UNK-001"] [])).Posture
assertEqual "unknown" Indeterminate (derive at (assessment Unknown [eid "E1"] [] [])).Posture
assertEqual "stale" Indeterminate (derive at (assessment Stale [eid "E1"] [] [])).Posture
assertEqual "missing-evidence" Indeterminate (derive at (assessment Verified [] [] [])).Posture
let contradiction={ invariant Verified [eid "E1"] with ContradictoryEvidence=[eid "E2"] }
assertEqual "contradiction" Indeterminate (derive at { Invariants=[contradiction]; UnknownSecurityEffects=Set.empty; Exceptions=[] }).Posture
let active={Id="EX-1";Approved=true;ExpiresAt=at.AddDays(1);Covers=Set.ofList["SEC-INV-001"]}
assertEqual "exception" Conditional (derive at (assessment Violated [eid "E1"] [] [active])).Posture
let expired={active with ExpiresAt=at.AddDays(-1)}
assertEqual "expired-exception" Blocked (derive at (assessment Violated [eid "E1"] [] [expired])).Posture
if Environment.ExitCode=0 then printfn "Tutela.Core gate tests passed"


let sha256 = String.replicate 64 "a"
assertEqual "sha256-digest-valid" true (ArtifactDigest.create Sha256 sha256 |> Result.isOk)
assertEqual "sha256-digest-short-rejected" true (ArtifactDigest.create Sha256 "aaa" |> Result.isError)
assertEqual "sha512-needs-128" true (ArtifactDigest.create Sha512 sha256 |> Result.isError)

let aliceOld = PlatformIdentity.github Human 12345UL (Some "alice") |> Result.defaultWith failwith
let aliceRenamed = PlatformIdentity.github Human 12345UL (Some "alice-new") |> Result.defaultWith failwith
let impostor = PlatformIdentity.github Human 54321UL (Some "alice") |> Result.defaultWith failwith
assertEqual "rename-preserves-subject" true (PlatformIdentity.sameSubject aliceOld aliceRenamed)
assertEqual "login-cannot-confer-authority" false (PlatformIdentity.sameSubject aliceOld impostor)
let membership = { Identity=aliceOld; Roles=Set.ofList[SecurityOwner]; ValidFrom=None; ValidUntil=None }
let registry = RoleRegistry.create "deny" [membership] |> Result.defaultWith failwith
assertEqual "matching-subject-role" (Set.ofList[SecurityOwner]) (RoleRegistry.rolesAt at aliceRenamed registry)
assertEqual "same-login-different-subject-no-role" Set.empty (RoleRegistry.rolesAt at impostor registry)
assertEqual "permissive-role-registry-rejected" true (RoleRegistry.create "allow" [] |> Result.isError)
