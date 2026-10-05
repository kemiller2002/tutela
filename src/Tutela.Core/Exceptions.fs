namespace Tutela.Core

open System

/// Exception approval is the narrowest path from BLOCKED to CONDITIONAL, so it
/// is evaluated against the role registry rather than the assessment's claims.
/// Requirements: TUT-1103, TUT-1104, TUT-1105, TUT-1204, TUT-0006.
module ExceptionApproval =
    /// Accepting risk is a security-owner decision (TUT-1103: explicit human
    /// decision); a security-reviewer may approve trust-root changes but not
    /// accept risk on the project's behalf.
    let requiredRole = SecurityOwner

    let private window at (e: ExceptionRecord) =
        [ match e.ExpiresAt with
          | None -> InvalidExpiry
          | Some expires when expires <= at -> Expired
          | Some _ -> ()
          match e.CreatedAt with
          | None -> InvalidCreation
          | Some created when created > at -> NotYetValid
          | Some created when e.ExpiresAt |> Option.exists (fun expires -> created >= expires) -> InvalidCreation
          | Some _ -> () ]

    let private completeness (e: ExceptionRecord) =
        [ if e.Covers.IsEmpty
             || e.Rationale |> Option.forall String.IsNullOrWhiteSpace
             || e.CompensatingControls.IsEmpty
             || e.Evidence.IsEmpty then IncompleteRecord ]

    let private identity at (registry: Result<RoleRegistry, string>) (e: ExceptionRecord) =
        [ if e.RequestedBy.IsNone then RequesterUnbound
          match e.ApproverIdentity with
          | None -> ApproverUnbound
          | Some approver ->
              if PlatformIdentity.kind approver <> Human then ApproverNotHuman
              match e.RequestedBy with
              | Some author when PlatformIdentity.sameSubject author approver -> SelfApproval
              | _ -> ()
              let roles = registry |> Result.map (RoleRegistry.rolesAt at approver) |> Result.defaultValue Set.empty
              if not (roles.Contains requiredRole) then ApproverLacksRole ]

    /// Every reason the exception cannot satisfy a gate at `at`. Empty means honored.
    let rejections at registry (e: ExceptionRecord) : ExceptionRejection list =
        [ if not e.Approved then NotApproved ]
        @ window at e
        @ completeness e
        @ identity at registry e

    let evaluate at registry (e: ExceptionRecord) : ExceptionDecision =
        match rejections at registry e with
        | [] -> Honored e
        | reasons -> Rejected (e, reasons)

    let honored decisions = decisions |> List.choose (function Honored e -> Some e | Rejected _ -> None)
