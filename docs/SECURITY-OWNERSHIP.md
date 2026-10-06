# Security ownership: Tutela is the single owner

Tutela owns security meaning across the Echelon portfolio (TUT-1702, TUT-1705).
That covers security policy, sensitive-data rules, evidence interpretation,
exceptions and release posture. Other repositories may *apply* Tutela rules. They
must not define competing ones. When a consumer needs a rule Tutela lacks, it is
raised against this repository (TUT-1706), not added locally.

## Canonical artifacts

| Artifact | Contract | Purpose |
|---|---|---|
| `security/SENSITIVE-DATA-RULES.json` | `tutela.sensitive-data-rules/1` | sensitive key names (`TUTELA-SD-K*`) and credential value shapes (`TUTELA-SD-V*`) |
| `schemas/verification-result.schema.json` | `tutela.verification/1` | gate verdict, findings with stable rule ids, exception outcomes |
| `schemas/security-evidence.schema.json` | Tutela Security Evidence | one evidence item in an assessment (`security-assessment.schema.json` `evidence[]`) |
| `tutela scan-secrets` output | `tutela.secret-scan/1` | secret-scan evidence (rule id, path, line; values never emitted) |
| `tutela trace` output | `tutela.traceability/1` | requirement-to-test traceability counts |

`schemas/evidence.schema.json` is not a Tutela artifact. Tutela's evidence schema
moved to `schemas/security-evidence.schema.json` (transition TR-2026-0003) because
Praxis installs its own schema at the old path. The trust-root policy protects the
new path; the old path belongs to Praxis.

The gate itself applies the catalog to assessment evidence. A sensitive key gives
"evidence contains a sensitive field", and a credential-shaped value gives
"evidence contains a sensitive value" (TUT-0103, TUT-0401). Tutela's own CI runs
`tutela scan-secrets` over every tracked file and fails on any finding.

## Divergent rules found elsewhere (to defer to Tutela)

These were found during the 2026-10-05 quality inventory. They are recorded here
for the owning repositories to act on; this change does not edit them.

| Repository | Location | Current local rule | Should defer to |
|---|---|---|---|
| Praxis | `src/Praxis.Domain/Remote/Protocol.fs` `SecretMaterial.looksLikeSecret` (failure `secret-detected`) | 8 value regexes with no ids. `sk-` has no word boundary, so "task-..." text can false-positive. | `TUTELA-SD-V001` ... `V008`. Load the catalog, or a pinned copy verified by digest, and report the Tutela rule id in the failure. |
| Praxis | `src/Praxis.Domain/Telemetry/Tutela.fs` (`TutelaSnapshot`) | projection with no ingest path | read `tutela.verification/1` (verdict, findings by `ruleId`, exception outcomes) instead of re-deriving posture |
| Aegis | `src/Aegis.Core/Redaction.fs` `defaultRules` | substring key list (token, password, passwd, secret, apikey, api-key, api_key, authorization, auth-header, cookie, session, privatekey, private-key, private_key, credential, bearer, signature) | `TUTELA-SD-K001` ... `K007` as the minimum set. Substring matching is a stricter local choice and may remain. Aegis-only terms (`session`, `signature`) should be proposed to the catalog or recorded as Aegis redaction extensions. Value redaction should add `TUTELA-SD-V*`. |
| Aegis | `src/Aegis.Core/Tutela.fs` `tryProjectFault` (`tutela/evidence/v1`) | emits evidence | needs a rule in `security/PROVENANCE-AUTHORITY.json` before its evidence can support Verified. That is a trust-root change requiring independent approval. |

Previously Tutela's own list (`SENSITIVE_KEYS` in `src/tutela_gate.py`) lacked
`passwd` and `api-key`. The catalog is the union of the Tutela and Aegis exact-key
sets, plus common token, secret and private-key spellings.

## Not in scope here

- No portfolio repository runs secret scanning, dependency review or CodeQL in
  CI. Tutela now scans itself. Rolling the scan out to other repositories, and
  feeding its output to assessments as `SecretScan` evidence, belongs to those
  repositories or to Conditor (TUT-1407).
- The scan matches patterns in the current tree only. It does not inspect git
  history, binaries or encoded values. A clean scan is not evidence of absence
  (TUT-0004).
