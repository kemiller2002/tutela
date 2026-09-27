namespace Tutela.Core

open System

module Gate =
    let private validExceptions at (assessment: Assessment) =
        assessment.Exceptions |> List.filter (fun e -> e.Approved && e.ExpiresAt > at)

    let validate (assessment: Assessment) =
        let duplicateIds =
            assessment.Invariants
            |> List.groupBy (fun x -> InvariantId.value x.Id)
            |> List.choose (fun (id, xs) -> if List.length xs > 1 then Some (ValidationError $"duplicate invariant id {id}") else None)
        let invalidVerified =
            assessment.Invariants
            |> List.collect (fun x ->
                let id = InvariantId.value x.Id
                [ if x.State = Verified && List.isEmpty x.Evidence then ValidationError $"{id} cannot be Verified without evidence"
                  if x.State = Verified && not (List.isEmpty x.ContradictoryEvidence) then ValidationError $"{id} cannot be Verified with contradictory evidence" ])
        duplicateIds @ invalidVerified

    let derive at assessment =
        match validate assessment with
        | errors when not (List.isEmpty errors) ->
            { Posture = Indeterminate
              Reasons = errors |> List.map (fun (ValidationError e) -> "invalid assessment: " + e) }
        | _ ->
            let exceptions = validExceptions at assessment
            let accepted = exceptions |> List.collect (fun e -> Set.toList e.Covers) |> Set.ofList
            let violated = assessment.Invariants |> List.filter (fun x -> x.State = Violated) |> List.map (fun x -> InvariantId.value x.Id)
            let hard = (violated @ Set.toList assessment.UnknownSecurityEffects) |> List.filter (accepted.Contains >> not)
            if not (List.isEmpty hard) then { Posture = Blocked; Reasons = hard }
            else
                let uncertain =
                    assessment.Invariants
                    |> List.filter (fun x -> x.State = Unknown || x.State = Stale)
                    |> List.map (fun x -> InvariantId.value x.Id)
                    |> List.filter (accepted.Contains >> not)
                if not (List.isEmpty uncertain) then { Posture = Indeterminate; Reasons = uncertain }
                elif not (List.isEmpty exceptions) then { Posture = Conditional; Reasons = exceptions |> List.map _.Id }
                else { Posture = Pass; Reasons = [] }
