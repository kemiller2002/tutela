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

type SecurityException =
    { Id: string
      Approved: bool
      ExpiresAt: DateTimeOffset
      Covers: Set<string> }

type Assessment =
    { Invariants: InvariantResult list
      UnknownSecurityEffects: Set<string>
      Exceptions: SecurityException list }

type Derivation =
    { Posture: Posture
      Reasons: string list }

type ValidationError = ValidationError of string


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

    let authorizes evidence (DenyByDefault rules) =
        rules |> List.exists (fun rule ->
            rule.EvidenceTypes.Contains evidence.EvidenceType
            && rule.ProvenanceKinds.Contains evidence.Provenance.Kind
            && rule.Issuers.Contains evidence.Provenance.Issuer
            && rule.ProducerIdentityKinds.Contains evidence.ProducerIdentity.Kind)
