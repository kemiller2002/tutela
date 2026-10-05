# Known Risks

- Foundation schemas and executable gate logic are not yet complete.
- Independent-verifier attestation mechanism is specified but not implemented.
- Aegis/Praxis/Forma/Folio/Conditor integration contracts require implementation in their owning repositories.
- Initial threat model is not exhaustive.
- No claim of security is made by this foundation.
- The F# gate port reproduces the Python oracle on the parity corpus, but no independent verifier has reviewed it yet (TUT-0006). Until that review, equivalence is evidenced only by tests written in the same change.
- `security/ROLE-REGISTRY.json` has no memberships. No exception can be honored, and no trust-root change can be approved through the gate, until the owner records verified role holders.
- 77 of 108 requirements have no test reference (requirements/TRACEABILITY-BASELINE.json). A test reference is a claim to review, not proof of complete coverage.
- The secret scan matches patterns in the current tree only. It does not inspect git history, binaries or encoded values.
