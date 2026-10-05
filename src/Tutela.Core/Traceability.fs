namespace Tutela.Core

open System.Text.RegularExpressions

/// Where a requirement id is referenced.
type RequirementTrace =
    { Id: string
      Tests: string list
      Code: string list }

type TraceStatus =
    | WithinRatchet
    | RatchetExceeded of baseline: int * actual: int

type TraceReport =
    { Requirements: RequirementTrace list
      MaxUntested: int option
      Status: TraceStatus }

/// Requirement-to-test traceability. A requirement counts as tested only when a
/// file under tests/ names its id; a reference in src/ is recorded separately
/// and never counted as test coverage. The report is a ratchet, not a gate on
/// coverage itself: the untested count may fall but must not rise.
module Traceability =
    [<Literal>]
    let Schema = "tutela.traceability/1"

    let private definition = Regex(@"^(TUT-\d{4})\b", RegexOptions.Multiline ||| RegexOptions.CultureInvariant)
    let private reference = Regex(@"\bTUT-\d{4}\b", RegexOptions.CultureInvariant)

    /// Requirement ids defined at the start of a line in the requirements text.
    let requirementIds (text: string) =
        definition.Matches text |> Seq.map _.Groups.[1].Value |> Seq.distinct |> Seq.toList

    let private referencesIn (files: (string * string) list) =
        files
        |> List.collect (fun (path, text) -> reference.Matches text |> Seq.map (fun m -> m.Value, path) |> Seq.distinct |> Seq.toList)
        |> List.groupBy fst
        |> List.map (fun (id, xs) -> id, xs |> List.map snd |> List.distinct |> List.sort)
        |> Map.ofList

    let untested report = report.Requirements |> List.filter (fun r -> r.Tests.IsEmpty)

    let build (requirements: string list) (testFiles: (string * string) list) (codeFiles: (string * string) list) (maxUntested: int option) =
        let tests = referencesIn testFiles
        let code = referencesIn codeFiles
        let lookup m id = Map.tryFind id m |> Option.defaultValue []
        let traces = requirements |> List.map (fun id -> { Id = id; Tests = lookup tests id; Code = lookup code id })
        let actual = traces |> List.filter (fun r -> r.Tests.IsEmpty) |> List.length
        { Requirements = traces
          MaxUntested = maxUntested
          Status =
            match maxUntested with
            | Some baseline when actual > baseline -> RatchetExceeded (baseline, actual)
            | _ -> WithinRatchet }

    let toJson (report: TraceReport) =
        let count f = report.Requirements |> List.filter f |> List.length
        let tested = count (fun r -> not r.Tests.IsEmpty)
        let codeOnly = count (fun r -> r.Tests.IsEmpty && not r.Code.IsEmpty)
        let none = count (fun r -> r.Tests.IsEmpty && r.Code.IsEmpty)
        JObject
            [ "schema", Json.str Schema
              "requirementsTotal", JNumber (decimal report.Requirements.Length)
              "tracedByTests", JNumber (decimal tested)
              "referencedInCodeOnly", JNumber (decimal codeOnly)
              "unreferenced", JNumber (decimal none)
              "untested", JNumber (decimal (codeOnly + none))
              "maxUntested", (match report.MaxUntested with Some n -> JNumber (decimal n) | None -> JNull)
              "status",
                Json.str (
                    match report.Status with
                    | WithinRatchet -> "within-ratchet"
                    | RatchetExceeded _ -> "ratchet-exceeded")
              "untestedIds", report |> untested |> List.map _.Id |> Json.strList
              "requirements",
                report.Requirements
                |> List.map (fun r -> JObject [ "id", Json.str r.Id; "tests", Json.strList r.Tests; "code", Json.strList r.Code ])
                |> JArray ]
