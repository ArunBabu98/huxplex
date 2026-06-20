<!-- Thanks for contributing to Huxplex. Keep PRs small and focused. -->

## What & why

<!-- What does this change do, and why? Link the issue/RFC/ADR it implements. -->

Closes #
Related ADR / RFC / spec:

## Type of change

- [ ] Crypto / security-sensitive (requires extra review — see SECURITY.md)
- [ ] Protocol behavior (consensus / state / networking)
- [ ] Documentation / specification
- [ ] Tooling / CI
- [ ] Refactor (no behavior change)

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] New/changed behavior is covered by tests
- [ ] If this changes a cryptographic context string, key size, or wire format,
      [`docs/15-specifications/`](../docs/15-specifications/) is updated **and** an
      ADR/RFC records the decision
- [ ] No secret/key material is committed

## Security & determinism notes

<!-- For consensus/crypto changes: note any impact on determinism, domain
     separation, or the threat model. Write "n/a" if not applicable. -->
