/// Tutela command-line boundary. All external effects (filesystem, clock, git
/// process) live here; decisions are delegated to the pure Tutela.Core modules
/// (TUT-1806). Exit codes: 0 pass/conditional, 1 blocked/indeterminate/findings,
/// 2 usage error or declared-posture mismatch, 3 unavailable.
module Tutela.Cli.Program

open System
open System.Diagnostics
open System.IO
open System.Security.Cryptography
open System.Text
open Tutela.Core

let toolVersion = "0.2.0"

[<Literal>]
let UsageExit = 2

let usage =
    """usage:
  tutela gate <assessment.json> [--check-declared] [--format verification|legacy]
              [--at <ISO-8601 instant>] [--policy-root <dir>] [--output <path>]
  tutela <assessment.json> [--check-declared]          (legacy envelope)
  tutela scan-secrets [--root <dir>] [--catalog <path>] [--output <path>] [<file>...]
  tutela trace [--root <dir>] [--baseline <path>] [--output <path>]

exit codes: 0 pass/conditional/clean, 1 blocked/indeterminate/findings,
            2 usage or declared-posture mismatch, 3 unavailable"""

// ---------------------------------------------------------------- arguments

type Options =
    { Positional: string list
      Flags: Set<string>
      Values: Map<string, string> }

let private valued = set [ "--format"; "--at"; "--policy-root"; "--output"; "--root"; "--catalog"; "--baseline" ]

let rec private parseArgs (options: Options) = function
    | [] -> Ok { options with Positional = List.rev options.Positional }
    | flag :: value :: rest when valued.Contains flag -> parseArgs { options with Values = options.Values.Add(flag, value) } rest
    | flag :: _ when valued.Contains flag -> Error $"{flag} requires a value"
    | "--check-declared" :: rest -> parseArgs { options with Flags = options.Flags.Add "--check-declared" } rest
    | (flag: string) :: _ when flag.StartsWith "--" -> Error $"unknown option {flag}"
    | value :: rest -> parseArgs { options with Positional = value :: options.Positional } rest

let private emptyOptions = { Positional = []; Flags = Set.empty; Values = Map.empty }

// ---------------------------------------------------------------- effects

let private readFile path =
    try Ok (File.ReadAllText path) with ex -> Error $"cannot read {path}: {ex.Message}"

let private sha256Hex (text: string) =
    (SHA256.HashData(Encoding.UTF8.GetBytes text) |> Convert.ToHexString).ToLowerInvariant()

let private write (output: string option) (text: string) =
    match output with
    | Some path -> File.WriteAllText(path, text + "\n")
    | None -> Console.Out.WriteLine text

let private gitFiles root : Result<string list, string> =
    try
        let info =
            ProcessStartInfo(
                "git",
                "ls-files -z --cached --others --exclude-standard",
                WorkingDirectory = root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false)
        use proc = Process.Start info
        let out = proc.StandardOutput.ReadToEnd()
        proc.WaitForExit()
        if proc.ExitCode <> 0 then Error "git ls-files failed"
        else Ok (out.Split('\000', StringSplitOptions.RemoveEmptyEntries) |> Array.toList)
    with ex -> Error $"git unavailable: {ex.Message}"

let private loadJson path =
    readFile path |> Result.bind (fun text -> Json.parse text |> Result.mapError (fun e -> $"{path}: {e}"))

let private policyFiles =
    [ "provenance-authority", "security/PROVENANCE-AUTHORITY.json"
      "trust-root-change", "security/TRUST-ROOT-CHANGE.json"
      "role-registry", "security/ROLE-REGISTRY.json"
      "sensitive-data-rules", "security/SENSITIVE-DATA-RULES.json" ]

/// Loads every policy document; any unreadable document makes the gate unavailable.
let private loadPolicy root : Result<GatePolicy * PolicyInput list, string> =
    result {
        let! documents =
            policyFiles
            |> ResultList.traverse (fun (name, rel) ->
                readFile (Path.Combine(root, rel))
                |> Result.bind (fun text ->
                    Json.parse text
                    |> Result.mapError (fun e -> $"{rel}: {e}")
                    |> Result.map (fun json -> name, json, { Name = name; Path = rel; Sha256 = sha256Hex text })))
        let doc name = documents |> List.pick (fun (n, json, _) -> if n = name then Some json else None)
        let! catalog = SensitiveData.parse (doc "sensitive-data-rules") |> Result.mapError (fun e -> $"sensitive-data catalog: {e}")
        let policy =
            { Authority = AuthorityPolicyDocument.parse (doc "provenance-authority")
              TrustRoot = TrustRootPolicyDocument.parse (doc "trust-root-change")
              Roles = RoleRegistryDocument.parse (doc "role-registry")
              Sensitive = catalog }
        return policy, documents |> List.map (fun (_, _, input) -> input)
    }

// ---------------------------------------------------------------- gate

let private unparseable (e: string) =
    let message = $"assessment is not valid JSON: {e}"
    { Derivation = { Posture = Indeterminate; Reasons = [ "invalid assessment: " + message ] }
      ValidationErrors = [ ValidationError (RuleIds.AssessmentStructure, message) ]
      ExceptionDecisions = []
      StaleEvidence = []
      Assessment = None }

let private evaluateFile (options: Options) format path (at: DateTimeOffset) =
    let render (result: VerificationResult) =
        (if format = "legacy" then Verification.legacyJson result else Verification.toJson result)
        |> Json.serialize true
        |> write (options.Values.TryFind "--output")
    let policyRoot = options.Values.TryFind "--policy-root" |> Option.defaultValue (Directory.GetCurrentDirectory())
    match readFile path, loadPolicy policyRoot with
    | Error e, _
    | _, Error e ->
        let result = Verification.unavailable at toolVersion (Some path) e
        render result
        eprintfn "tutela: evaluation unavailable: %s" e
        Verification.exitCode result.Verdict
    | Ok text, Ok (policy, inputs) ->
        let document = Json.parse text
        let evaluation =
            match document with
            | Ok json -> Gate.evaluate at policy json
            | Error e -> unparseable e
        let json = document |> Result.defaultValue JNull
        let subject =
            let s = Json.orEmptyObject "subject" json
            match Json.stringOf "repository" s, Json.stringOf "ref" s with
            | Some repository, Some reference -> Some (repository, reference)
            | _ -> None
        let declared = Json.stringOf "posture" json
        let derived = Verification.postureText evaluation.Derivation.Posture
        let result = Verification.ofEvaluation at toolVersion (Some path) (Some (sha256Hex text)) subject declared inputs evaluation
        render result
        if options.Flags.Contains "--check-declared" && declared <> Some derived then
            eprintfn "declared posture %s != derived posture %s" (defaultArg declared "None") derived
            UsageExit
        else Verification.exitCode result.Verdict

let private runGate legacyDefault (options: Options) =
    let format = options.Values.TryFind "--format" |> Option.defaultValue (if legacyDefault then "legacy" else "verification")
    let at =
        match options.Values.TryFind "--at" with
        | Some text -> Time.parse text
        | None -> Ok DateTimeOffset.UtcNow
    match options.Positional, at with
    | _ when format <> "verification" && format <> "legacy" ->
        eprintfn "--format must be verification or legacy"
        UsageExit
    | _, Error e ->
        eprintfn "--at: %s" e
        UsageExit
    | [ path ], Ok at -> evaluateFile options format path at
    | _ ->
        eprintfn "%s" usage
        UsageExit

// ---------------------------------------------------------------- secret scan

let private runScan (options: Options) =
    let root = options.Values.TryFind "--root" |> Option.defaultValue (Directory.GetCurrentDirectory())
    let catalogPath = options.Values.TryFind "--catalog" |> Option.defaultValue (Path.Combine(root, "security/SENSITIVE-DATA-RULES.json"))
    let output = options.Values.TryFind "--output"
    let s = Json.str
    let report =
        result {
            let! catalog = loadJson catalogPath |> Result.bind SensitiveData.parse
            let! files = if options.Positional.IsEmpty then gitFiles root else Ok options.Positional
            let! contents =
                files
                |> List.filter (fun f -> File.Exists(Path.Combine(root, f)))
                |> ResultList.traverse (fun f -> readFile (Path.Combine(root, f)) |> Result.map (fun text -> f, text))
            return catalog, contents.Length, contents |> List.collect (fun (f, text) -> SensitiveData.scanText catalog f text)
        }
    match report with
    | Error e ->
        JObject [ "schema", s "tutela.secret-scan/1"; "verdict", s "unavailable"; "reason", s e ] |> Json.serialize true |> write output
        eprintfn "tutela: secret scan unavailable: %s" e
        3
    | Ok (catalog, scanned, findings) ->
        JObject
            [ "schema", s "tutela.secret-scan/1"
              "catalog", JObject [ "id", s catalog.Id; "version", s catalog.Version ]
              "scannedFiles", JNumber (decimal scanned)
              "verdict", s (if findings.IsEmpty then "pass" else "blocked")
              "findings",
                findings
                |> List.map (fun f -> JObject [ "ruleId", s f.RuleId; "path", s f.Path; "line", JNumber (decimal f.Line) ])
                |> JArray
              "limitations",
                Json.strList
                    [ "Pattern scan of the listed files at one point in time; it does not inspect git history, binaries or encoded values."
                      "A clean scan is not evidence that no secret exists." ] ]
        |> Json.serialize true
        |> write output
        findings |> List.iter (fun f -> eprintfn "%s:%d: %s (value redacted)" f.Path f.Line f.RuleId)
        if findings.IsEmpty then 0 else 1

// ---------------------------------------------------------------- traceability

let private isBuildOutput (path: string) =
    let p = path.Replace('\\', '/')
    p.Contains "/obj/" || p.Contains "/bin/Release/" || p.Contains "/bin/Debug/"

let private sourceExtensions = set [ ".fs"; ".fsx"; ".py"; ".mjs"; ".js"; ".ts" ]

let private runTrace (options: Options) =
    let root = options.Values.TryFind "--root" |> Option.defaultValue (Directory.GetCurrentDirectory())
    let baselinePath =
        options.Values.TryFind "--baseline" |> Option.defaultValue (Path.Combine(root, "requirements/TRACEABILITY-BASELINE.json"))
    let report =
        result {
            let! requirements = readFile (Path.Combine(root, "requirements/TUTELA-REQUIREMENTS.md")) |> Result.map Traceability.requirementIds
            let! baseline = loadJson baselinePath
            let! files = gitFiles root
            let sources =
                files
                |> List.filter (fun f ->
                    sourceExtensions.Contains(Path.GetExtension f) && not (isBuildOutput f) && File.Exists(Path.Combine(root, f)))
            let! contents = sources |> ResultList.traverse (fun f -> readFile (Path.Combine(root, f)) |> Result.map (fun t -> f, t))
            let tests, code = contents |> List.partition (fun (f, _) -> f.StartsWith "tests/")
            let maxUntested =
                match Json.get "maxUntested" baseline with
                | Some (JNumber n) -> Some (int n)
                | _ -> None
            return Traceability.build requirements tests code maxUntested
        }
    match report with
    | Error e ->
        eprintfn "tutela: traceability unavailable: %s" e
        3
    | Ok report ->
        Traceability.toJson report |> Json.serialize true |> write (options.Values.TryFind "--output")
        let untested = Traceability.untested report |> List.length
        match report.Status, report.MaxUntested with
        | RatchetExceeded (baseline, actual), _ ->
            eprintfn "traceability ratchet exceeded: %d untested requirements, baseline allows %d" actual baseline
            1
        | WithinRatchet, Some baseline when untested < baseline ->
            eprintfn "traceability improved: %d untested (baseline %d); lower maxUntested to lock it in" untested baseline
            0
        | WithinRatchet, _ -> 0

[<EntryPoint>]
let main argv =
    let run command args =
        match parseArgs emptyOptions args with
        | Error e ->
            eprintfn "%s\n%s" e usage
            UsageExit
        | Ok options -> command options
    match List.ofArray argv with
    | "gate" :: rest -> run (runGate false) rest
    | "scan-secrets" :: rest -> run runScan rest
    | "trace" :: rest -> run runTrace rest
    | ("-h" | "--help") :: _ ->
        printfn "%s" usage
        0
    | [] ->
        eprintfn "%s" usage
        UsageExit
    | args -> run (runGate true) args
