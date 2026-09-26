# Tutela

Tutela is Echelon Foundry's security engineering discipline. It turns security claims into explicit invariants, threats, controls, evidence, unknowns, and release decisions.

Tutela never asserts that a system is secure. It establishes which defined security properties are supported by current evidence, which are violated, and which remain unknown.

Core model: Asset -> Trust Boundary -> Threat -> Security Invariant -> Control -> Evidence -> Finding/Unknown -> Release Posture.

Integrates with Ordo/SDE, ROS, Aegis, Praxis, Forma, Folio, Limen and Conditor.

## Run an adversarial campaign

Tutela includes a repository-local campaign entry point:

```sh
./bin/tutela-campaign campaign.json authorization.json --bundle-out campaign-result.json --evidence-out adversarial-evidence.json
```

Execution is fail-closed and requires an authorization bound to the campaign, immutable subject reference and environment. HTTP scenarios additionally require an explicitly authorized origin. Production authorization is rejected by the current harness.

Exit codes are deterministic for CI: `0` means the executed campaign produced no violation or unresolved coverage, `2` means at least one scenario violated an expected invariant, `3` means execution or coverage remains indeterminate, and `4` means the campaign was not executed because input/authorization/runtime setup was invalid. These codes describe campaign evidence, not a general claim that the application is secure.
