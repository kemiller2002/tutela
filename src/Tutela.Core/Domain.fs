namespace Tutela.Core

open System

type Posture = Pass | Conditional | Blocked | Indeterminate

type InvariantState = Verified | Violated | Unknown | Stale | NotApplicable

type EvidenceId = private EvidenceId of string
module EvidenceId =
    let create value = if String.IsNullOrWhiteSpace value then Error "evidence id is required" else Ok (EvidenceId value)
    let value (EvidenceId value) = value

type InvariantId = private InvariantId of string
module InvariantId =
    let create value = if String.IsNullOrWhiteSpace value then Error "invariant id is required" else Ok (InvariantId value)
    let value (InvariantId value) = value

type InvariantResult =
    { Id: InvariantId
      State: InvariantState
      Evidence: EvidenceId list
      ContradictoryEvidence: EvidenceId list }


type Derivation =
    { Posture: Posture
      Reasons: string list }

/// A validation failure: the stable gate rule id and the reference-oracle message.
type ValidationError = ValidationError of ruleId: string * message: string


type DigestAlgorithm = Sha256 | Sha512

type ArtifactDigest = private ArtifactDigest of DigestAlgorithm * string
module ArtifactDigest =
    let create algorithm value =
        let expected = match algorithm with Sha256 -> 64 | Sha512 -> 128
        let isHex = value |> Seq.forall Uri.IsHexDigit
        if String.IsNullOrWhiteSpace value || value.Length <> expected || not isHex then Error "digest does not match algorithm"
        else Ok (ArtifactDigest (algorithm, value.ToLowerInvariant()))
    let algorithm (ArtifactDigest (a,_)) = a
    let value (ArtifactDigest (_,v)) = v

type ProducerIdentity = { Kind: string; Value: string }

type Provenance =
    { Kind: string
      Issuer: string
      RunRef: string
      WorkflowRef: string option }

type Evidence =
    { Id: EvidenceId
      EvidenceType: string
      Producer: string
      ProducerIdentity: ProducerIdentity
      SubjectRef: string
      ObservedAt: DateTimeOffset
      ArtifactDigest: ArtifactDigest
      Provenance: Provenance
      ValidUntil: DateTimeOffset option
      InvalidatedAt: DateTimeOffset option
      InvalidationReason: string option }

type AuthorityRule =
    { Id: string
      EvidenceTypes: Set<string>
      ProvenanceKinds: Set<string>
      Issuers: Set<string>
      ProducerIdentityKinds: Set<string> }

type AuthorityPolicy =
    private
    | DenyByDefault of AuthorityRule list

module AuthorityPolicy =
    let create defaultDecision rules =
        if defaultDecision <> "deny" then Error "provenance authority policy must default deny"
        else Ok (DenyByDefault rules)

    /// Deny unless one rule names every attribute. A missing attribute never matches.
    let authorizesRaw evidenceType provenanceKind issuer producerIdentityKind (DenyByDefault rules) =
        let within (set: Set<string>) value = value |> Option.exists set.Contains
        rules |> List.exists (fun rule ->
            within rule.EvidenceTypes evidenceType
            && within rule.ProvenanceKinds provenanceKind
            && within rule.Issuers issuer
            && within rule.ProducerIdentityKinds producerIdentityKind)

    let authorizes evidence policy =
        authorizesRaw (Some evidence.EvidenceType) (Some evidence.Provenance.Kind) (Some evidence.Provenance.Issuer) (Some evidence.ProducerIdentity.Kind) policy


type IdentityKind = Human | Agent | Workflow

type PlatformIdentity =
    private
    | GitHubIdentity of IdentityKind * uint64 * string option

module PlatformIdentity =
    let github kind subjectId login =
        if subjectId = 0UL then Error "GitHub subject id must be a positive immutable numeric account id"
        else Ok (GitHubIdentity(kind, subjectId, login))
    let provider _ = "github"
    let subjectId (GitHubIdentity(_,id,_)) = id
    let kind (GitHubIdentity(k,_,_)) = k
    let login (GitHubIdentity(_,_,login)) = login
    let sameSubject a b = provider a = provider b && subjectId a = subjectId b

type Role = SecurityReviewer | SecurityOwner

type RoleMembership =
    { Identity: PlatformIdentity
      Roles: Set<Role>
      ValidFrom: DateTimeOffset option
      ValidUntil: DateTimeOffset option }

type RoleRegistry =
    private
    | DenyByDefaultRoles of RoleMembership list

module RoleRegistry =
    let create defaultDecision memberships =
        if defaultDecision <> "deny" then Error "security role registry must default deny"
        else Ok (DenyByDefaultRoles memberships)

    let rolesAt at identity (DenyByDefaultRoles memberships) =
        memberships
        |> List.filter (fun m ->
            PlatformIdentity.sameSubject identity m.Identity
            && (m.ValidFrom |> Option.forall (fun t -> t <= at))
            && (m.ValidUntil |> Option.forall (fun t -> t > at)))
        |> List.collect (fun m -> Set.toList m.Roles)
        |> Set.ofList


/// Timestamps in assessments and policies. An offset is mandatory: a naive
/// local time cannot be ordered against the evaluation instant, so it is
/// rejected rather than guessed.
module Time =
    let private offsetSuffix = Text.RegularExpressions.Regex(@"(Z|[+-]\d{2}:\d{2})$", Text.RegularExpressions.RegexOptions.CultureInvariant)

    let parse (value: string) : Result<DateTimeOffset, string> =
        let normalized = value.Replace("Z", "+00:00")
        if String.IsNullOrWhiteSpace value || not (offsetSuffix.IsMatch normalized) then Error $"timestamp {value} must carry an explicit UTC offset"
        else
            match DateTimeOffset.TryParse(normalized, Globalization.CultureInfo.InvariantCulture, Globalization.DateTimeStyles.None) with
            | true, t -> Ok t
            | _ -> Error $"timestamp {value} is not ISO-8601"

    let format (t: DateTimeOffset) = t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", Globalization.CultureInfo.InvariantCulture)

/// A security exception as written in an assessment. Nothing in this record is
/// trusted: `Approved` and both identities are claims until
/// `ExceptionApproval.evaluate` checks them against the role registry.
type ExceptionRecord =
    { Id: string
      Approved: bool
      CreatedAt: DateTimeOffset option
      ExpiresAt: DateTimeOffset option
      Covers: string list
      Rationale: string option
      CompensatingControls: string list
      Evidence: string list
      /// The exception author. None when absent or not a verified binding.
      RequestedBy: PlatformIdentity option
      /// The approver. None when absent or not a verified binding.
      ApproverIdentity: PlatformIdentity option }

/// Why an exception cannot satisfy a gate. Codes are stable contract values.
type ExceptionRejection =
    | NotApproved
    | InvalidExpiry
    | Expired
    | InvalidCreation
    | NotYetValid
    | IncompleteRecord
    | RequesterUnbound
    | ApproverUnbound
    | ApproverNotHuman
    | SelfApproval
    | ApproverLacksRole

module ExceptionRejection =
    let code = function
        | NotApproved -> "not-approved"
        | InvalidExpiry -> "invalid-expiry"
        | Expired -> "expired"
        | InvalidCreation -> "invalid-creation"
        | NotYetValid -> "not-yet-valid"
        | IncompleteRecord -> "incomplete-record"
        | RequesterUnbound -> "requester-unbound"
        | ApproverUnbound -> "approver-unbound"
        | ApproverNotHuman -> "approver-not-human"
        | SelfApproval -> "self-approval"
        | ApproverLacksRole -> "approver-lacks-role"

type ExceptionDecision =
    | Honored of ExceptionRecord
    | Rejected of ExceptionRecord * ExceptionRejection list

type Assessment =
    { Invariants: InvariantResult list
      /// Kept as a list: order is part of the deterministic reason output.
      UnknownSecurityEffects: string list
      Exceptions: ExceptionRecord list }
