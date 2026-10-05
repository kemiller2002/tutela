namespace Tutela.Core

/// Stable gate rule identifiers published in `tutela.verification/1` findings.
/// Identifiers are never reused or renumbered; a retired rule keeps its id.
/// The catalog is documented in docs/VERIFICATION-CONTRACT.md.
module RuleIds =
    // Policy inputs
    [<Literal>]
    let RoleRegistryDefaultDeny = "TUTELA-G001"
    [<Literal>]
    let AuthorityPolicyDefaultDeny = "TUTELA-G002"
    // Assessment structure
    [<Literal>]
    let AssessmentStructure = "TUTELA-G010"
    [<Literal>]
    let SchemaVersion = "TUTELA-G011"
    [<Literal>]
    let SubjectRequired = "TUTELA-G012"
    [<Literal>]
    let GateWeakening = "TUTELA-G013"
    [<Literal>]
    let InvariantStructure = "TUTELA-G014"
    [<Literal>]
    let ThreatStructure = "TUTELA-G015"
    [<Literal>]
    let ExceptionStructure = "TUTELA-G016"
    // Invariant evidence
    [<Literal>]
    let VerifiedWithoutEvidence = "TUTELA-G020"
    [<Literal>]
    let ContradictoryEvidence = "TUTELA-G021"
    [<Literal>]
    let IndependentVerification = "TUTELA-G022"
    // Evidence integrity
    [<Literal>]
    let EvidenceStructure = "TUTELA-G030"
    [<Literal>]
    let EvidenceDigest = "TUTELA-G031"
    [<Literal>]
    let EvidenceProvenance = "TUTELA-G032"
    [<Literal>]
    let EvidenceAuthority = "TUTELA-G033"
    [<Literal>]
    let EvidenceSubjectBinding = "TUTELA-G034"
    [<Literal>]
    let EvidenceInvalidation = "TUTELA-G035"
    [<Literal>]
    let UndeclaredEvidence = "TUTELA-G036"
    [<Literal>]
    let StaleEvidence = "TUTELA-G037"
    [<Literal>]
    let EvidenceTime = "TUTELA-G038"
    // Trust root
    [<Literal>]
    let TrustRootChange = "TUTELA-G040"
    // Posture derivation
    [<Literal>]
    let ViolatedInvariant = "TUTELA-G100"
    [<Literal>]
    let UnknownSecurityEffect = "TUTELA-G101"
    [<Literal>]
    let UnknownInvariant = "TUTELA-G102"
    [<Literal>]
    let StaleInvariant = "TUTELA-G103"
    [<Literal>]
    let MissingEvidence = "TUTELA-G104"
    [<Literal>]
    let ExceptionHonored = "TUTELA-G110"
    // Exception approval (one id per rejection reason)
    let exceptionRejection = function
        | NotApproved -> "TUTELA-G200"
        | InvalidExpiry -> "TUTELA-G201"
        | Expired -> "TUTELA-G202"
        | InvalidCreation -> "TUTELA-G203"
        | NotYetValid -> "TUTELA-G204"
        | IncompleteRecord -> "TUTELA-G205"
        | RequesterUnbound -> "TUTELA-G206"
        | ApproverUnbound -> "TUTELA-G207"
        | ApproverNotHuman -> "TUTELA-G208"
        | SelfApproval -> "TUTELA-G209"
        | ApproverLacksRole -> "TUTELA-G210"
    // Declared posture and evaluation availability
    [<Literal>]
    let DeclaredPostureMismatch = "TUTELA-G300"
    [<Literal>]
    let EvaluationUnavailable = "TUTELA-G900"
