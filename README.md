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


## Install Tutela into another repository

From a Tutela checkout, bootstrap a target repository with:

```sh
./bin/tutela-install /path/to/target --repository owner/repository --ref HEAD
```

The bootstrap is non-destructive by default. It creates a repository-local `.tutela/security-assessment.json`, starter adversarial coverage file, a pinned copy of the deterministic gate under `.tutela/runtime/`, and `.github/workflows/tutela-security.yml`. Existing files are preserved. `--force` is required to replace them.

A new installation deliberately starts INDETERMINATE. The bootstrap records an unknown invariant and unresolved repository-specific security review. Adoption therefore cannot create a PASS merely by installing tooling. The repository must define its actual assets, boundaries, threats, invariants, evidence and adversarial coverage before its posture can improve.
