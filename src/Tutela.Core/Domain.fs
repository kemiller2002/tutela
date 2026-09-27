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
