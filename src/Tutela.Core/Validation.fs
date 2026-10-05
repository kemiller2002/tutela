namespace Tutela.Core

open System

/// The policy inputs the gate evaluates against. Loaded at the boundary; a
/// permissive (non-deny) registry or authority policy is carried as an Error so
/// validation reports it and nothing is authorized by it.
type GatePolicy =
    { Authority: Result<AuthorityPolicy, string>
      TrustRoot: TrustRootPolicy
      Roles: Result<RoleRegistry, string>
      Sensitive: SensitiveDataCatalog }

/// Semantic validation of an untrusted assessment document. This is the F#
/// port of `validate()` in src/tutela_gate.py (the conformance oracle). Error
/// messages and their order are kept identical so the two implementations can
/// be compared exactly (tests/parity). Requirements: TUT-0007, TUT-1804, TUT-1807.
module Validation =
    let private err rule message = ValidationError (rule, message)

    let private invariantStates = set [ "Verified"; "Violated"; "Unknown"; "Stale"; "NotApplicable" ]

    let private isHex (s: string) = s |> Seq.forall Uri.IsHexDigit

    let validDigest digest =
        match Json.stringOf "algorithm" digest, Json.get "value" digest with
        | Some alg, Some (JString v) when alg = "sha256" || alg = "sha512" ->
            v.Length = (if alg = "sha256" then 64 else 128) && isHex v
        | _ -> false

    let private registeredRoles at (policy: GatePolicy) identityJson =
        match Identity.tryBind identityJson, policy.Roles with
        | Some identity, Ok registry -> RoleRegistry.rolesAt at identity registry |> Set.map RoleRegistryDocument.roleText
        | _ -> Set.empty

    let private approvalAuthorized at policy weakening approval =
        let identity = Json.orEmptyObject "approverIdentity" approval
        let role = Json.get "role" approval
        let roleText = role |> Option.bind Json.tryString
        let hasRole = roleText |> Option.exists (registeredRoles at policy identity).Contains
        hasRole
        && policy.TrustRoot.ApprovalAuthorities
           |> List.exists (fun rule ->
               (Json.stringOf "kind" identity |> Option.exists rule.IdentityKinds.Contains)
               && (roleText |> Option.exists rule.Roles.Contains)
               && rule.MayApprove.Contains "trust-root-change"
               && (not weakening || rule.MayAuthorizeWeakening))

    let private trustRootChange at (policy: GatePolicy) (change: JsonValue option) =
        match change with
        | None -> []
        | Some change when not (Json.truthy change) -> []
        | Some change ->
            let touched = Json.strings "paths" change |> Set.ofList
            if Set.intersect touched policy.TrustRoot.ProtectedPaths |> Set.isEmpty then []
            else
                let r = RuleIds.TrustRootChange
                let required =
                    [ "id"; "rationale"; "changedBy"; "changedByIdentity"; "previousDigest"; "newDigest" ]
                    |> List.filter (fun k -> not (Json.has k change))
                    |> List.map (fun k -> err r $"trustRootChange.{k} is required")
                let digests =
                    [ "previousDigest"; "newDigest" ]
                    |> List.filter (fun k -> Json.has k change && not (validDigest (Json.getOr k JNull change)))
                    |> List.map (fun k -> err r $"trustRootChange.{k} must be an exact sha256/sha512 digest")
                let noop =
                    [ if Json.has "previousDigest" change && Json.equalOpt (Json.get "previousDigest" change) (Json.get "newDigest" change) then
                          err r "trustRootChange digests must describe an actual transition" ]
                let changedBySubject = Json.orEmptyObject "changedByIdentity" change |> Identity.rawSubjectId
                let independent =
                    Json.orEmptyArray "approvals" change
                    |> Json.items
                    |> List.filter (fun x ->
                        Json.isObject x
                        && Json.isTrue "approved" x
                        && Json.has "approverIdentity" x
                        && Json.has "evidence" x
                        && Identity.rawSubjectId (Json.getOr "approverIdentity" JNull x) <> changedBySubject
                        && approvalAuthorized at policy false x)
                let approvals =
                    [ if independent.Length < policy.TrustRoot.ApprovalsMinimum then
                          err r "protected trust-root change requires independent approval evidence" ]
                let weakening =
                    if not (Json.isTrue "weakening" change) then []
                    else
                        [ if not (Json.isTrue "weakeningExplicitlyAuthorized" change) then
                              err r "trust-root weakening requires explicit authorization"
                          if not (independent |> List.exists (approvalAuthorized at policy true)) then
                              err r "trust-root weakening requires an authorized security-owner approval" ]
                required @ digests @ noop @ approvals @ weakening

    let private sensitive (policy: GatePolicy) evidence =
        match SensitiveData.find policy.Sensitive evidence with
        | Some (SensitiveKey rule) -> [ err rule "evidence contains a sensitive field" ]
        | Some (SensitiveValue rule) -> [ err rule "evidence contains a sensitive value" ]
        | None -> []

    let private policyBlock a =
        match Json.get "policy" a with
        | Some p when Json.truthy p ->
            if not (Json.isObject p) then [ err RuleIds.AssessmentStructure "policy must be an object" ]
            else
                [ if not (Json.has "id" p) || not (Json.has "version" p) then
                      err RuleIds.AssessmentStructure "policy.id and policy.version are required when policy is supplied"
                  if Json.isTrue "allowGateWeakening" p then err RuleIds.GateWeakening "assessment cannot authorize gate weakening" ]
        | _ -> []

    let private subjectOf a = Json.orEmptyObject "subject" a

    let private subjectBlock a =
        let subject = subjectOf a
        if not (Json.isObject subject) then [ err RuleIds.SubjectRequired "subject must be an object" ]
        else
            [ if not (Json.has "repository" subject) then err RuleIds.SubjectRequired "subject.repository is required"
              if not (Json.has "ref" subject) then err RuleIds.SubjectRequired "subject.ref is required" ]

    let private independentAttestation iidOrP (x: JsonValue) =
        let attestations = Json.orEmptyArray "verifierAttestations" x |> Json.items
        let independent =
            attestations
            |> List.filter (fun v ->
                Json.isObject v && Json.isTrue "independent" v && Json.has "verifier" v && Json.has "evidence" v
                && Json.has "verifierIdentity" v && Json.has "separationBasis" v)
        let r = RuleIds.IndependentVerification
        let perAttestation =
            independent
            |> List.collect (fun v ->
                let vi = Json.orEmptyObject "verifierIdentity" v
                let implementedBy = Json.get "implementedBy" x
                [ if not (Json.isObject vi && Json.has "type" vi && Json.has "value" vi) then
                      err r $"{iidOrP} independent verifier identity is incomplete"
                  if Json.equalOpt (Json.get "verifier" v) implementedBy || Json.equalOpt (Json.get "value" vi) implementedBy then
                      err r $"{iidOrP} verifier is not independent of implementer" ])
        perAttestation @ [ if independent.IsEmpty then err r $"{iidOrP} requires an independent verifier attestation" ]

    let private invariantsBlock a =
        match Json.get "invariantResults" a with
        | Some (JArray inv) ->
            inv
            |> List.indexed
            |> List.fold (fun (ids: Set<JsonValue>, acc) (i, x) ->
                let p = $"invariantResults[{i}]"
                if not (Json.isObject x) then ids, acc @ [ err RuleIds.InvariantStructure $"{p} must be an object" ]
                else
                    let iid = Json.get "id" x |> Option.map Json.normalize
                    let idErrors, ids' =
                        match iid with
                        | Some v when Json.truthy v && ids.Contains v -> [ err RuleIds.InvariantStructure $"duplicate invariant id {Json.pyStr v}" ], ids
                        | Some v when Json.truthy v -> [], ids.Add v
                        | _ -> [ err RuleIds.InvariantStructure $"{p}.id is required" ], ids
                    let label = match iid with Some v when Json.truthy v -> Json.pyStr v | _ -> p
                    let state = Json.stringOf "state" x
                    let verified = state = Some "Verified"
                    let errors =
                        idErrors
                        @ [ if not (state |> Option.exists invariantStates.Contains) then err RuleIds.InvariantStructure $"{p}.state is invalid"
                            if verified && not (Json.has "evidence" x) then err RuleIds.VerifiedWithoutEvidence $"{label} cannot be Verified without evidence"
                            if verified && Json.has "contradictoryEvidence" x then err RuleIds.ContradictoryEvidence $"{label} cannot be Verified with contradictory evidence" ]
                        @ (if verified && Json.isTrue "requiresIndependentVerification" x then independentAttestation label x else [])
                    ids', acc @ errors) (Set.empty, [])
            |> snd
        | _ -> [ err RuleIds.InvariantStructure "invariantResults must be an array" ]

    let private evidenceBlock at (policy: GatePolicy) a =
        let subject = subjectOf a
        match Json.getOr "evidence" (JArray []) a with
        | JArray items ->
            let objects = items |> List.filter Json.isObject
            let ids = items |> List.map (fun e -> if Json.isObject e then Json.getOr "id" JNull e else e) |> List.map Json.normalize
            let known = Set.ofList ids
            let r = RuleIds.EvidenceStructure
            let header =
                [ if items |> List.exists (Json.isObject >> not) then
                      err r "evidence entries must be structured objects; bare evidence references are not sufficient"
                  if ids.Length <> known.Count then err r "duplicate evidence id" ]
            let perEvidence =
                objects
                |> List.collect (fun e ->
                    let eid = match Json.get "id" e with Some v when Json.truthy v -> Json.pyStr v | _ -> "evidence"
                    let required =
                        [ "id"; "producer"; "producerIdentity"; "subjectRef"; "observedAt"; "artifactDigest"; "provenance" ]
                        |> List.filter (fun k -> not (Json.has k e))
                        |> List.map (fun k -> err r $"{eid}.{k} is required")
                    let digest = Json.orEmptyObject "artifactDigest" e
                    let provenance = Json.orEmptyObject "provenance" e
                    let identity = Json.orEmptyObject "producerIdentity" e
                    let authorized =
                        match policy.Authority with
                        | Ok authority ->
                            AuthorityPolicy.authorizesRaw
                                (Json.stringOf "type" e)
                                (Json.stringOf "kind" provenance)
                                (Json.stringOf "issuer" provenance)
                                (Json.stringOf "type" identity)
                                authority
                        | Error _ -> false
                    let digestValue = Json.get "value" digest
                    let subjectHash =
                        match Json.get "artifactHash" subject with
                        | Some sd when Json.truthy sd -> Some (if Json.isObject sd then Json.getOr "value" JNull sd else sd)
                        | _ -> None
                    required
                    @ [ if Json.isObject digest && Json.truthy digest && not (validDigest digest && Json.has "value" digest) then
                            err RuleIds.EvidenceDigest $"{eid}.artifactDigest requires sha256/sha512 algorithm and value"
                        if Json.isObject provenance && Json.truthy provenance
                           && not (Json.has "kind" provenance && Json.has "issuer" provenance && Json.has "runRef" provenance) then
                            err RuleIds.EvidenceProvenance $"{eid}.provenance requires kind, issuer and runRef"
                        if not authorized then
                            err RuleIds.EvidenceAuthority $"{eid} provenance issuer is not authorized for evidence type and producer identity"
                        if Json.isObject identity && Json.truthy identity && not (Json.has "type" identity && Json.has "value" identity) then
                            err RuleIds.EvidenceProvenance $"{eid}.producerIdentity requires type and value"
                        match Json.has "artifactDigest" e, subjectHash with
                        | true, Some normalized when Json.truthy normalized && not (Json.equalOpt digestValue (Some normalized)) ->
                            err RuleIds.EvidenceSubjectBinding $"{eid} artifact digest does not match subject artifactHash"
                        | _ -> ()
                        if Json.has "subjectRef" e && not (Json.equalOpt (Json.get "subjectRef" e) (Json.get "ref" subject)) then
                            err RuleIds.EvidenceSubjectBinding $"{eid} is bound to a different subject ref"
                        if Json.has "invalidatedAt" e && not (Json.has "invalidationReason" e) then
                            err RuleIds.EvidenceInvalidation $"{eid} invalidation requires a reason" ])
            let references =
                match Json.get "invariantResults" a with
                | Some (JArray inv) when not known.IsEmpty ->
                    inv
                    |> List.filter Json.isObject
                    |> List.collect (fun x ->
                        let label = Json.get "id" x |> Option.map Json.pyStr |> Option.defaultValue "invariant"
                        (Json.orEmptyArray "evidence" x |> Json.items) @ (Json.orEmptyArray "contradictoryEvidence" x |> Json.items)
                        |> List.filter (Json.normalize >> known.Contains >> not)
                        |> List.map (fun eid -> err RuleIds.UndeclaredEvidence $"{label} references undeclared evidence {Json.pyStr eid}"))
                | _ -> []
            header @ perEvidence @ references
        | _ -> [ err RuleIds.EvidenceStructure "evidence must be an array when supplied" ]

    let private threatsBlock a =
        match Json.getOr "threats" (JArray []) a with
        | JArray xs -> [ if xs.Length <> (xs |> List.map Json.normalize |> Set.ofList).Count then err RuleIds.ThreatStructure "duplicate threat id" ]
        | _ -> [ err RuleIds.ThreatStructure "threats must be an array when supplied" ]

    let private exceptionsBlock a =
        match Json.getOr "exceptions" (JArray []) a with
        | JArray xs ->
            xs
            |> List.indexed
            |> List.collect (fun (i, e) ->
                if not (Json.isObject e) then [ err RuleIds.ExceptionStructure $"exceptions[{i}] must be an object" ]
                else
                    [ "id"; "approver"; "expiresAt" ]
                    |> List.filter (fun k -> not (Json.has k e))
                    |> List.map (fun k -> err RuleIds.ExceptionStructure $"exceptions[{i}].{k} is required"))
        | _ -> [ err RuleIds.ExceptionStructure "exceptions must be an array" ]

    /// Structural checks the reference oracle does not make because it would
    /// crash on them. The F# authority fails closed instead (TUT-0007).
    let private hardening a =
        [ match Json.get "unknownSecurityEffects" a with
          | None | Some (JArray _) -> ()
          | Some _ -> err RuleIds.AssessmentStructure "unknownSecurityEffects must be an array" ]

    let validate (at: DateTimeOffset) (policy: GatePolicy) (a: JsonValue) : ValidationError list =
        if not (Json.isObject a) then [ err RuleIds.AssessmentStructure "assessment must be a JSON object" ]
        else
            [ match policy.Roles with
              | Error _ -> err RuleIds.RoleRegistryDefaultDeny "security role registry must default deny"
              | Ok _ -> () ]
            @ trustRootChange at policy (Json.get "trustRootChange" a)
            @ [ match policy.Authority with
                | Error _ -> err RuleIds.AuthorityPolicyDefaultDeny "provenance authority policy must default deny"
                | Ok _ -> ()
                if Json.get "schemaVersion" a <> Some (JNumber 1m) then err RuleIds.SchemaVersion "schemaVersion must be 1" ]
            @ policyBlock a
            @ sensitive policy (Json.getOr "evidence" (JArray []) a)
            @ subjectBlock a
            @ invariantsBlock a
            @ evidenceBlock at policy a
            @ threatsBlock a
            @ exceptionsBlock a
            @ hardening a
