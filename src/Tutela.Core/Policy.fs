namespace Tutela.Core

open System

/// Interpretation of identity bindings and of the security policy documents
/// (provenance authority, trust-root change, role registry). Every function is
/// pure: callers load the documents at the boundary and pass them in.
module Identity =
    let private kindOf = function
        | "human" -> Some Human
        | "agent" -> Some Agent
        | "workflow" -> Some Workflow
        | _ -> None

    let kindText = function Human -> "human" | Agent -> "agent" | Workflow -> "workflow"

    /// The subject id exactly as the reference oracle renders it with `str()`.
    let rawSubjectId identity = Json.get "subjectId" identity |> Json.pyStrOpt

    /// Canonical positive decimal without leading zeros, so numeric equality and
    /// string equality agree and "007" cannot alias "7".
    let private canonicalSubjectId = function
        | Some (JString s) when s.Length > 0 && s.Length <= 20 && Seq.forall Char.IsAsciiDigit s && s.[0] <> '0' ->
            match UInt64.TryParse s with
            | true, v -> Some v
            | _ -> None
        | Some (JNumber n) when n > 0m && n = Math.Truncate n && n <= decimal UInt64.MaxValue -> Some (uint64 n)
        | _ -> None

    let private githubObservation evidence =
        Json.isObject evidence
        && Json.stringOf "kind" evidence = Some "platform-api-observation"
        && Json.stringOf "issuer" evidence = Some "github"
        && Json.has "sourceRef" evidence
        && Json.has "observedAt" evidence

    /// A verified platform binding, or None. A display login never confers
    /// identity; only provider + immutable subject id with platform evidence.
    let tryBind (identity: JsonValue) : PlatformIdentity option =
        if not (Json.isObject identity) || not (Json.has "provider" identity) || not (Json.isTrue "bindingVerified" identity) then None
        else
            let evidence = Json.orEmptyArray "bindingEvidence" identity |> Json.items
            match Json.stringOf "provider" identity, canonicalSubjectId (Json.get "subjectId" identity), Json.stringOf "kind" identity |> Option.bind kindOf with
            | Some "github", Some subjectId, Some kind when evidence |> List.exists githubObservation ->
                PlatformIdentity.github kind subjectId (Json.stringOf "login" identity) |> Result.toOption
            | _ -> None

module RoleRegistryDocument =
    let private roleOf = function
        | "security-reviewer" -> Some SecurityReviewer
        | "security-owner" -> Some SecurityOwner
        | _ -> None

    let roleText = function SecurityReviewer -> "security-reviewer" | SecurityOwner -> "security-owner"
    let tryRole (s: string) = roleOf s

    let private optionalTime key value =
        match Json.get key value with
        | None | Some JNull -> Ok None
        | Some (JString s) when s = "" -> Ok None
        | Some (JString s) -> Time.parse s |> Result.map Some
        | Some _ -> Error $"{key} must be a timestamp"

    /// Memberships with an unverified identity or an unreadable validity window
    /// confer nothing (deny by default).
    let parse (document: JsonValue) : Result<RoleRegistry, string> =
        let memberships =
            Json.getOr "memberships" (JArray []) document
            |> Json.items
            |> List.choose (fun m ->
                match Identity.tryBind (Json.orEmptyObject "identity" m), optionalTime "validFrom" m, optionalTime "validUntil" m with
                | Some identity, Ok validFrom, Ok validUntil ->
                    Some { Identity = identity
                           Roles = Json.strings "roles" m |> List.choose roleOf |> Set.ofList
                           ValidFrom = validFrom
                           ValidUntil = validUntil }
                | _ -> None)
        RoleRegistry.create (Json.stringOf "default" document |> Option.defaultValue "") memberships

module AuthorityPolicyDocument =
    let parse (document: JsonValue) : Result<AuthorityPolicy, string> =
        let set key rule = Json.strings key rule |> Set.ofList
        let rules =
            Json.getOr "authorities" (JArray []) document
            |> Json.items
            |> List.map (fun rule ->
                { Id = Json.stringOf "id" rule |> Option.defaultValue ""
                  EvidenceTypes = set "evidenceTypes" rule
                  ProvenanceKinds = set "provenanceKinds" rule
                  Issuers = set "issuers" rule
                  ProducerIdentityKinds = set "producerIdentityTypes" rule })
        AuthorityPolicy.create (Json.stringOf "default" document |> Option.defaultValue "") rules

type ApprovalAuthority =
    { Id: string
      Roles: Set<string>
      MayApprove: Set<string>
      MayAuthorizeWeakening: bool
      IdentityKinds: Set<string> }

type TrustRootPolicy =
    { ProtectedPaths: Set<string>
      ApprovalsMinimum: int
      ApprovalAuthorities: ApprovalAuthority list }

module TrustRootPolicyDocument =
    let parse (document: JsonValue) : TrustRootPolicy =
        let minimum =
            match Json.orEmptyObject "requirements" document |> Json.get "approvalsMinimum" with
            | Some (JNumber n) -> int n
            | _ -> 1
        { ProtectedPaths = Json.strings "protectedPaths" document |> Set.ofList
          // A policy can raise the bar but never lower it below one approval.
          ApprovalsMinimum = max 1 minimum
          ApprovalAuthorities =
            Json.getOr "approvalAuthorities" (JArray []) document
            |> Json.items
            |> List.map (fun a ->
                { Id = Json.stringOf "id" a |> Option.defaultValue ""
                  Roles = Json.strings "roles" a |> Set.ofList
                  MayApprove = Json.strings "mayApprove" a |> Set.ofList
                  MayAuthorizeWeakening = Json.isTrue "mayAuthorizeWeakening" a
                  IdentityKinds = Json.strings "identityKinds" a |> Set.ofList }) }
