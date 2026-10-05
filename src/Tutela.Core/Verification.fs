namespace Tutela.Core

open System

/// Contract verdict. Consumers MUST treat anything other than `pass` and
/// `conditional` as not releasable; `unavailable` means the gate could not
/// evaluate and is never a pass.
type Verdict =
    | VerdictPass
    | VerdictConditional
    | VerdictBlocked
    | VerdictIndeterminate
    | VerdictUnavailable

type Severity =
    | Blocking
    | Undetermined
    | Advisory

type Finding =
    { RuleId: string
      Severity: Severity
      Subject: string option
      Message: string }

type ExceptionOutcome =
    { Id: string
      Honored: bool
      Covers: string list
      ExpiresAt: DateTimeOffset option
      Rejections: ExceptionRejection list }

/// A policy document the verdict depended on, bound by digest.
type PolicyInput =
    { Name: string
      Path: string
      Sha256: string }

type VerificationResult =
    { EvaluatedAt: DateTimeOffset
      ToolVersion: string
      AssessmentPath: string option
      AssessmentSha256: string option
      Subject: (string * string) option
      Verdict: Verdict
      Posture: Posture option
      Reasons: string list
      DeclaredPosture: string option
      Findings: Finding list
      Exceptions: ExceptionOutcome list
      Policies: PolicyInput list }

/// `tutela.verification/1`: the versioned, machine-readable result contract.
/// Schema: schemas/verification-result.schema.json. Owner: Tutela.
module Verification =
    [<Literal>]
    let Schema = "tutela.verification/1"

    let postureText = function
        | Pass -> "PASS"
        | Conditional -> "CONDITIONAL"
        | Blocked -> "BLOCKED"
        | Indeterminate -> "INDETERMINATE"

    let verdictOf = function
        | Pass -> VerdictPass
        | Conditional -> VerdictConditional
        | Blocked -> VerdictBlocked
        | Indeterminate -> VerdictIndeterminate

    let verdictText = function
        | VerdictPass -> "pass"
        | VerdictConditional -> "conditional"
        | VerdictBlocked -> "blocked"
        | VerdictIndeterminate -> "indeterminate"
        | VerdictUnavailable -> "unavailable"

    let severityText = function Blocking -> "blocking" | Undetermined -> "indeterminate" | Advisory -> "advisory"

    /// Exit codes: 0 pass/conditional, 1 blocked/indeterminate, 3 unavailable.
    /// (2 is reserved for usage errors and declared-posture mismatch.)
    let exitCode = function
        | VerdictPass | VerdictConditional -> 0
        | VerdictBlocked | VerdictIndeterminate -> 1
        | VerdictUnavailable -> 3

    let private finding rule severity subject message =
        { RuleId = rule; Severity = severity; Subject = subject; Message = message }

    let private derivationFindings (assessment: Assessment) (decisions: ExceptionDecision list) =
        let accepted = ExceptionApproval.honored decisions |> List.collect _.Covers |> Set.ofList
        let covered id = accepted.Contains id
        let severityFor normal id = if covered id then Advisory else normal
        let suffix id = if covered id then " (covered by an honored exception)" else ""
        let byState state rule severity text =
            assessment.Invariants
            |> List.filter (fun x -> x.State = state)
            |> List.map (fun x ->
                let id = InvariantId.value x.Id
                finding rule (severityFor severity id) (Some id) $"{id} {text}{suffix id}")
        let missing =
            assessment.Invariants
            |> List.filter (fun x -> x.State = Verified && x.Evidence.IsEmpty)
            |> List.map (fun x ->
                let id = InvariantId.value x.Id
                finding RuleIds.MissingEvidence (severityFor Undetermined id) (Some id) $"{id} is Verified without evidence{suffix id}")
        let unknownEffects =
            assessment.UnknownSecurityEffects
            |> List.map (fun id -> finding RuleIds.UnknownSecurityEffect (severityFor Blocking id) (Some id) $"unknown security effect {id}{suffix id}")
        let exceptions =
            decisions
            |> List.collect (function
                | Honored e -> [ finding RuleIds.ExceptionHonored Advisory (Some e.Id) $"exception {e.Id} honored for {String.Join(',', e.Covers)}" ]
                | Rejected (e, reasons) ->
                    reasons
                    |> List.map (fun r ->
                        finding (RuleIds.exceptionRejection r) Advisory (Some e.Id) $"exception {e.Id} not honored: {ExceptionRejection.code r}"))
        byState Violated RuleIds.ViolatedInvariant Blocking "is Violated"
        @ unknownEffects
        @ byState Unknown RuleIds.UnknownInvariant Undetermined "is Unknown"
        @ byState Stale RuleIds.StaleInvariant Undetermined "is Stale"
        @ missing
        @ exceptions

    /// Findings for an evaluation, with stable rule ids.
    let findings (evaluation: Evaluation) =
        let validation =
            evaluation.ValidationErrors
            |> List.map (fun (ValidationError (rule, message)) -> finding rule Undetermined None message)
        match evaluation.Assessment with
        | Some assessment -> validation @ derivationFindings assessment evaluation.ExceptionDecisions
        | None when validation.IsEmpty ->
            evaluation.Derivation.Reasons |> List.map (finding RuleIds.StaleEvidence Undetermined None)
        | None -> validation

    let private outcome = function
        | Honored e -> { Id = e.Id; Honored = true; Covers = e.Covers; ExpiresAt = e.ExpiresAt; Rejections = [] }
        | Rejected (e, reasons) -> { Id = e.Id; Honored = false; Covers = e.Covers; ExpiresAt = e.ExpiresAt; Rejections = reasons }

    /// Builds a contract result from an evaluation.
    let ofEvaluation at toolVersion path digest subject declared policies (evaluation: Evaluation) =
        let declaredFinding =
            match declared with
            | Some d when d <> postureText evaluation.Derivation.Posture ->
                [ finding RuleIds.DeclaredPostureMismatch Advisory None $"declared posture {d} != derived posture {postureText evaluation.Derivation.Posture}" ]
            | _ -> []
        { EvaluatedAt = at
          ToolVersion = toolVersion
          AssessmentPath = path
          AssessmentSha256 = digest
          Subject = subject
          Verdict = verdictOf evaluation.Derivation.Posture
          Posture = Some evaluation.Derivation.Posture
          Reasons = evaluation.Derivation.Reasons
          DeclaredPosture = declared
          Findings = findings evaluation @ declaredFinding
          Exceptions = evaluation.ExceptionDecisions |> List.map outcome
          Policies = policies }

    /// A result for when the gate could not evaluate at all.
    let unavailable at toolVersion path reason =
        { EvaluatedAt = at
          ToolVersion = toolVersion
          AssessmentPath = path
          AssessmentSha256 = None
          Subject = None
          Verdict = VerdictUnavailable
          Posture = None
          Reasons = [ reason ]
          DeclaredPosture = None
          Findings = [ finding RuleIds.EvaluationUnavailable Undetermined None reason ]
          Exceptions = []
          Policies = [] }

    let limitations =
        [ "PASS is an evidence-scoped posture for the declared invariants only; it is not a claim that the subject is secure."
          "Absence of a finding is not evidence of absence. Unknown and stale states are reported, not resolved." ]

    let toJson (r: VerificationResult) : JsonValue =
        let s = Json.str
        let declaredMatches =
            match r.DeclaredPosture, r.Posture with
            | Some d, Some p -> JBool (d = postureText p)
            | _ -> JNull
        JObject
            [ "schema", s Schema
              "tool", JObject [ "name", s "tutela"; "version", s r.ToolVersion; "implementation", s "fsharp" ]
              "evaluatedAt", s (Time.format r.EvaluatedAt)
              "assessment",
                JObject
                    [ "path", Json.opt s r.AssessmentPath
                      "sha256", Json.opt s r.AssessmentSha256 ]
              "subject",
                (match r.Subject with
                 | Some (repository, reference) -> JObject [ "repository", s repository; "ref", s reference ]
                 | None -> JNull)
              "verdict", s (verdictText r.Verdict)
              "posture", Json.opt (postureText >> s) r.Posture
              "reasons", Json.strList r.Reasons
              "declaredPosture", Json.opt s r.DeclaredPosture
              "declaredMatches", declaredMatches
              "findings",
                r.Findings
                |> List.map (fun f ->
                    JObject
                        [ "ruleId", s f.RuleId
                          "severity", s (severityText f.Severity)
                          "subject", Json.opt s f.Subject
                          "message", s f.Message ])
                |> JArray
              "exceptions",
                r.Exceptions
                |> List.map (fun e ->
                    JObject
                        [ "id", s e.Id
                          "status", s (if e.Honored then "honored" else "rejected")
                          "covers", Json.strList e.Covers
                          "expiresAt", Json.opt (Time.format >> s) e.ExpiresAt
                          "rejections",
                            e.Rejections
                            |> List.map (fun x -> JObject [ "code", s (ExceptionRejection.code x); "ruleId", s (RuleIds.exceptionRejection x) ])
                            |> JArray ])
                |> JArray
              "policies",
                r.Policies
                |> List.map (fun p -> JObject [ "name", s p.Name; "path", s p.Path; "sha256", s p.Sha256 ])
                |> JArray
              "limitations", Json.strList limitations ]

    /// The legacy `{derivedPosture, reasons}` envelope shared with the Python oracle.
    let legacyJson (r: VerificationResult) =
        JObject
            [ "derivedPosture", (match r.Posture with Some p -> Json.str (postureText p) | None -> Json.str "INDETERMINATE")
              "reasons", Json.strList r.Reasons ]
