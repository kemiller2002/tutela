namespace Tutela.Core

open System

/// The outcome of evaluating one assessment document.
type Evaluation =
    { Derivation: Derivation
      /// Validation failures; non-empty means the posture is INDETERMINATE.
      ValidationErrors: ValidationError list
      /// Every exception's decision, honored or rejected with reasons.
      ExceptionDecisions: ExceptionDecision list
      /// Evidence ids that were stale or invalidated at evaluation time.
      StaleEvidence: string list
      /// The typed projection, when the document was valid enough to project.
      Assessment: Assessment option }

/// Deterministic release-posture derivation. Precedence (docs/GATE-SEMANTICS.md):
/// invalid -> INDETERMINATE; unaccepted violation or unknown effect -> BLOCKED;
/// unknown/stale invariant -> INDETERMINATE; honored exception -> CONDITIONAL;
/// otherwise PASS. Requirements: TUT-1201..TUT-1205, TUT-0003, TUT-0604.
module Gate =
    let private ids state (assessment: Assessment) =
        assessment.Invariants |> List.filter (fun x -> x.State = state) |> List.map (fun x -> InvariantId.value x.Id)

    /// Derives posture from a typed assessment. Exceptions are honored only when
    /// `ExceptionApproval` accepts them against the role registry at `at`.
    let deriveWithDecisions (at: DateTimeOffset) (registry: Result<RoleRegistry, string>) (assessment: Assessment) =
        let decisions = assessment.Exceptions |> List.map (ExceptionApproval.evaluate at registry)
        let honored = ExceptionApproval.honored decisions
        let accepted = honored |> List.collect _.Covers |> Set.ofList
        let unaccepted = List.filter (accepted.Contains >> not)
        let hard = ids Violated assessment @ assessment.UnknownSecurityEffects |> unaccepted
        let missing =
            assessment.Invariants
            |> List.filter (fun x -> x.State = Verified && x.Evidence.IsEmpty)
            |> List.map (fun x -> InvariantId.value x.Id)
        let uncertain = ids Unknown assessment @ ids Stale assessment @ missing |> unaccepted
        let derivation =
            if not hard.IsEmpty then { Posture = Blocked; Reasons = hard }
            elif not uncertain.IsEmpty then { Posture = Indeterminate; Reasons = uncertain }
            elif not honored.IsEmpty then { Posture = Conditional; Reasons = honored |> List.map _.Id }
            else { Posture = Pass; Reasons = [] }
        derivation, decisions

    let derive at registry assessment = deriveWithDecisions at registry assessment |> fst

    let private invalid errors =
        { Posture = Indeterminate
          Reasons = errors |> List.map (fun (ValidationError (_, e)) -> "invalid assessment: " + e) }

    let private stateOf = function
        | "Verified" -> Ok Verified
        | "Violated" -> Ok Violated
        | "Unknown" -> Ok Unknown
        | "Stale" -> Ok Stale
        | "NotApplicable" -> Ok NotApplicable
        | x -> Error $"invalid invariant state {x}"

    let private evidenceIds key x =
        Json.orEmptyArray key x |> Json.items |> ResultList.traverse (Json.pyStr >> EvidenceId.create)

    let private projectInvariant x =
        result {
            let! id = Json.get "id" x |> Json.pyStrOpt |> InvariantId.create
            let! state = Json.stringOf "state" x |> Option.defaultValue "" |> stateOf
            let! evidence = evidenceIds "evidence" x
            let! contradictory = evidenceIds "contradictoryEvidence" x
            return { Id = id; State = state; Evidence = evidence; ContradictoryEvidence = contradictory }
        }

    let private time key e =
        Json.stringOf key e |> Option.bind (Time.parse >> Result.toOption)

    let private nonEmptyStrings key e = Json.strings key e |> List.filter (fun s -> s <> "")

    let projectException (e: JsonValue) : ExceptionRecord =
        { Id = Json.get "id" e |> Json.pyStrOpt
          Approved = Json.isTrue "approved" e
          CreatedAt = time "createdAt" e
          ExpiresAt = time "expiresAt" e
          Covers = nonEmptyStrings "covers" e
          Rationale = Json.stringOf "rationale" e
          CompensatingControls = nonEmptyStrings "compensatingControls" e
          Evidence = nonEmptyStrings "evidence" e
          RequestedBy = Identity.tryBind (Json.getOr "requestedByIdentity" JNull e)
          ApproverIdentity = Identity.tryBind (Json.getOr "approverIdentity" JNull e) }

    /// Projects a validated document into the typed domain.
    let project (a: JsonValue) : Result<Assessment, string> =
        result {
            let! invariants = Json.getOr "invariantResults" (JArray []) a |> Json.items |> ResultList.traverse projectInvariant
            return
                { Invariants = invariants
                  UnknownSecurityEffects = Json.getOr "unknownSecurityEffects" (JArray []) a |> Json.items |> List.map Json.pyStr
                  Exceptions = Json.getOr "exceptions" (JArray []) a |> Json.items |> List.map projectException }
        }

    /// Evidence that is invalidated or past validUntil at `at`, in document order.
    /// An unreadable validUntil is an Error carrying the evidence id.
    let private staleEvidence at (a: JsonValue) : Result<string list, string> =
        Json.getOr "evidence" (JArray []) a
        |> Json.items
        |> List.filter (fun e -> Json.isObject e && Json.has "id" e)
        |> List.map (fun e -> Json.pyStr (Json.getOr "id" JNull e), e)
        |> ResultList.traverse (fun (eid, e) ->
            let invalidated = Json.has "invalidatedAt" e
            match Json.get "validUntil" e with
            | Some v when Json.truthy v ->
                match Json.tryString v |> Option.map Time.parse with
                | Some (Ok expires) -> Ok (eid, invalidated || expires <= at)
                | _ -> Error eid
            | _ -> Ok (eid, invalidated))
        |> Result.map (List.filter snd >> List.map fst)

    let private stopped derivation errors stale =
        { Derivation = derivation; ValidationErrors = errors; ExceptionDecisions = []; StaleEvidence = stale; Assessment = None }

    /// Evaluates an untrusted assessment document. Pure: the caller supplies
    /// the evaluation instant and the loaded policy.
    let evaluate (at: DateTimeOffset) (policy: GatePolicy) (a: JsonValue) : Evaluation =
        match Validation.validate at policy a with
        | (_ :: _) as errors -> stopped (invalid errors) errors []
        | [] ->
            match staleEvidence at a with
            | Error eid ->
                let message = $"invalid evidence time {eid}"
                stopped { Posture = Indeterminate; Reasons = [ message ] } [ ValidationError (RuleIds.EvidenceTime, message) ] []
            | Ok stale ->
                let staleSet = Set.ofList stale
                let reliesOnStale =
                    Json.getOr "invariantResults" (JArray []) a
                    |> Json.items
                    |> List.tryFind (fun x ->
                        Json.stringOf "state" x = Some "Verified"
                        && (Json.getOr "evidence" (JArray []) x |> Json.items |> List.exists (Json.pyStr >> staleSet.Contains)))
                match reliesOnStale with
                | Some x ->
                    let id = Json.get "id" x |> Json.pyStrOpt
                    stopped { Posture = Indeterminate; Reasons = [ $"{id} relies on stale or invalidated evidence" ] } [] stale
                | None ->
                    match project a with
                    | Error e ->
                        let errors = [ ValidationError (RuleIds.AssessmentStructure, e) ]
                        stopped (invalid errors) errors stale
                    | Ok assessment ->
                        let derivation, decisions = deriveWithDecisions at policy.Roles assessment
                        { Derivation = derivation
                          ValidationErrors = []
                          ExceptionDecisions = decisions
                          StaleEvidence = stale
                          Assessment = Some assessment }
