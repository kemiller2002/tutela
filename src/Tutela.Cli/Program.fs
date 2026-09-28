open System
open System.IO
open System.Text.Json
open Tutela.Core
open Tutela.Core.Gate

let postureText = function Pass -> "PASS" | Conditional -> "CONDITIONAL" | Blocked -> "BLOCKED" | Indeterminate -> "INDETERMINATE"
let stateOf = function
    | "Verified" -> Ok Verified | "Violated" -> Ok Violated | "Unknown" -> Ok Unknown
    | "Stale" -> Ok Stale | "NotApplicable" -> Ok NotApplicable | x -> Error $"invalid invariant state {x}"

let strings (e: JsonElement) name =
    match e.TryGetProperty name with
    | true,p when p.ValueKind=JsonValueKind.Array -> p.EnumerateArray() |> Seq.map _.GetString() |> Seq.choose id |> Seq.toList
    | _ -> []

let parseInvariant (x: JsonElement) =
    result {
        let! id = InvariantId.create (x.GetProperty("id").GetString())
        let! state = stateOf (x.GetProperty("state").GetString())
        let! evidence = strings x "evidence" |> List.map EvidenceId.create |> List.fold (fun s r -> Result.map2 (fun xs x -> x::xs) s r) (Ok []) |> Result.map List.rev
        let! contradictory = strings x "contradictoryEvidence" |> List.map EvidenceId.create |> List.fold (fun s r -> Result.map2 (fun xs x -> x::xs) s r) (Ok []) |> Result.map List.rev
        return { Id=id; State=state; Evidence=evidence; ContradictoryEvidence=contradictory }
    }

let parse path =
    try
        use doc=JsonDocument.Parse(File.ReadAllText path)
        let root=doc.RootElement
        let inv =
            root.GetProperty("invariantResults").EnumerateArray()
            |> Seq.map parseInvariant |> Seq.toList
            |> List.fold (fun s r -> Result.map2 (fun xs x -> x::xs) s r) (Ok []) |> Result.map List.rev
        Result.map (fun invariants ->
            { Invariants=invariants
              UnknownSecurityEffects=strings root "unknownSecurityEffects" |> Set.ofList
              Exceptions=[] }) inv
    with ex -> Error ex.Message

match Environment.GetCommandLineArgs() |> Array.skip 1 with
| [|path|] ->
    match parse path with
    | Error e -> printfn """{"derivedPosture":"INDETERMINATE","reasons":["invalid assessment: %s"]}""" (e.Replace(""","'")); Environment.ExitCode <- 1
    | Ok assessment ->
        let result=derive DateTimeOffset.UtcNow assessment
        printfn """{"derivedPosture":"%s","reasons":[%s]}""" (postureText result.Posture) (result.Reasons |> List.map (fun x -> JsonSerializer.Serialize x) |> String.concat ",")
        Environment.ExitCode <- if result.Posture=Blocked || result.Posture=Indeterminate then 1 else 0
| _ -> eprintfn "usage: tutela <assessment.json>"; Environment.ExitCode <- 2
