namespace Tutela.Core

open System
open System.Text.RegularExpressions

/// A sensitive key name rule. Keys match exactly, ignoring case.
type KeyRule =
    { Id: string
      Name: string
      Keys: Set<string> }

/// A sensitive value rule: a credential shape recognisable without context.
type ValueRule =
    { Id: string
      Name: string
      Pattern: Regex }

/// The canonical Tutela sensitive-data catalog (security/SENSITIVE-DATA-RULES.json).
type SensitiveDataCatalog =
    { Id: string
      Version: string
      KeyRules: KeyRule list
      ValueRules: ValueRule list }

type SensitiveMatch =
    | SensitiveKey of ruleId: string
    | SensitiveValue of ruleId: string

/// A secret-scan hit. The matched text is never carried, only its location.
type SecretFinding =
    { RuleId: string
      Path: string
      Line: int }

module SensitiveData =
    [<Literal>]
    let Schema = "tutela.sensitive-data-rules/1"

    let private timeout = TimeSpan.FromSeconds 2.0

    let private compile (pattern: string) =
        try Ok (Regex(pattern, RegexOptions.CultureInvariant, timeout))
        with ex -> Error $"invalid pattern: {ex.Message}"

    /// Parses the catalog. An empty or malformed catalog is an Error: a gate
    /// must not silently run without sensitive-data rules.
    let parse (document: JsonValue) : Result<SensitiveDataCatalog, string> =
        result {
            if Json.stringOf "schema" document <> Some Schema then return! Error $"sensitive-data catalog schema must be {Schema}"
            let keyRules =
                Json.getOr "keyRules" (JArray []) document
                |> Json.items
                |> List.map (fun r ->
                    { Id = Json.stringOf "id" r |> Option.defaultValue ""
                      Name = Json.stringOf "name" r |> Option.defaultValue ""
                      Keys = Json.strings "keys" r |> List.map _.ToLowerInvariant() |> Set.ofList })
            let! valueRules =
                Json.getOr "valueRules" (JArray []) document
                |> Json.items
                |> ResultList.traverse (fun r ->
                    match Json.stringOf "id" r, Json.stringOf "pattern" r with
                    | Some id, Some pattern when id <> "" && pattern <> "" ->
                        compile pattern |> Result.map (fun rx -> { Id = id; Name = Json.stringOf "name" r |> Option.defaultValue ""; Pattern = rx })
                    | _ -> Error "every value rule requires id and pattern")
            if keyRules.IsEmpty || valueRules.IsEmpty then return! Error "sensitive-data catalog must define key and value rules"
            if keyRules |> List.exists (fun r -> r.Id = "" || r.Keys.IsEmpty) then return! Error "every key rule requires id and keys"
            return
                { Id = Json.stringOf "id" document |> Option.defaultValue ""
                  Version = Json.stringOf "version" document |> Option.defaultValue ""
                  KeyRules = keyRules
                  ValueRules = valueRules }
        }

    let matchKey (catalog: SensitiveDataCatalog) (key: string) =
        let k = key.ToLowerInvariant()
        catalog.KeyRules |> List.tryFind (fun r -> r.Keys.Contains k)

    /// A regex timeout is treated as a match: fail closed.
    let matchValue (catalog: SensitiveDataCatalog) (value: string) =
        catalog.ValueRules
        |> List.tryFind (fun r ->
            try r.Pattern.IsMatch value
            with :? RegexMatchTimeoutException -> true)

    /// Depth-first search for a sensitive key or value, in document order.
    /// A key is checked before its value is descended into.
    let rec find (catalog: SensitiveDataCatalog) (value: JsonValue) : SensitiveMatch option =
        match value with
        | JObject members ->
            members
            |> List.tryPick (fun (k, v) ->
                match matchKey catalog k with
                | Some rule -> Some (SensitiveKey rule.Id)
                | None -> find catalog v)
        | JArray xs -> xs |> List.tryPick (find catalog)
        | JString s -> matchValue catalog s |> Option.map (fun r -> SensitiveValue r.Id)
        | _ -> None

    /// Scans one text file for credential-shaped values, line by line.
    let scanText (catalog: SensitiveDataCatalog) (path: string) (text: string) : SecretFinding list =
        if text.Contains '\000' then []
        else
            text.Split('\n')
            |> Array.toList
            |> List.indexed
            |> List.collect (fun (i, line) ->
                catalog.ValueRules
                |> List.filter (fun r ->
                    try r.Pattern.IsMatch line
                    with :? RegexMatchTimeoutException -> true)
                |> List.map (fun r -> { RuleId = r.Id; Path = path; Line = i + 1 }))
