#!/usr/bin/env bash
# Huxplex Layer 0 — one-command verification.
#
#   ./scripts/verify-layer0.sh
#
# Runs every check that must pass for Layer 0 to be considered sound on YOUR machine, and
# prints a PASS/FAIL summary. This is the script a developer or contributor runs to satisfy
# themselves that the foundation actually holds — not to trust a badge.
#
# Full explanation of each check: docs/19-verification/README.md
#
# Exit code 0 = every check passed. Anything else = at least one failed; the transcript above
# the summary says which.
set -uo pipefail

cd "$(dirname "$0")/.."

BOLD=$'\033[1m'; RESET=$'\033[0m'
GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'

declare -a NAMES=() RESULTS=()
failures=0

run() {
  local name="$1"; shift
  printf '\n%s▸ %s%s\n' "$BOLD" "$name" "$RESET"
  printf '%s  $ %s%s\n' "$DIM" "$*" "$RESET"
  if "$@" > /tmp/hux-verify-step.log 2>&1; then
    NAMES+=("$name"); RESULTS+=("PASS")
    printf '  %sPASS%s\n' "$GREEN" "$RESET"
  else
    NAMES+=("$name"); RESULTS+=("FAIL")
    failures=$((failures + 1))
    printf '  %sFAIL%s — output follows:\n' "$RED" "$RESET"
    sed 's/^/    /' /tmp/hux-verify-step.log | tail -40
  fi
}

# ── Preflight ────────────────────────────────────────────────────────────────────────────
printf '%sHuxplex Layer 0 verification%s\n' "$BOLD" "$RESET"
printf '  host arch    : %s\n' "$(uname -m)"
printf '  os           : %s\n' "$(uname -s)"
printf '  rustc        : %s\n' "$(rustc --version 2>/dev/null || echo 'NOT FOUND')"
printf '  cargo        : %s\n' "$(cargo --version 2>/dev/null || echo 'NOT FOUND')"
printf '  pinned       : %s\n' "$(grep -E '^channel' rust-toolchain.toml | cut -d'"' -f2)"
printf '  commit       : %s\n' "$(git rev-parse --short HEAD 2>/dev/null || echo 'not a git checkout')"

if ! command -v cargo > /dev/null; then
  printf '\n%sNo cargo on PATH.%s Install Rust from https://rustup.rs and re-run.\n' "$RED" "$RESET"
  exit 127
fi

# ── Checks ───────────────────────────────────────────────────────────────────────────────
run "Formatting is canonical"           cargo fmt --all --check
run "No clippy lints"                   cargo clippy --all-targets --all-features -- -D warnings
run "Crate layering is downward-only"   ./scripts/check-layering.sh
run "No arch-specific backend paths"    ./scripts/check-arch-portability.sh
run "Registry is the only primitive path" ./scripts/check-primitive-encapsulation.sh
run "Workspace builds"                  cargo build --all-targets --all-features --locked
run "Test suite"                        cargo test --all-targets --all-features --locked
run "Doctests"                          cargo test --doc --all-features --locked
run "Docs build without warnings"       env RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features
run "Crypto walkthrough self-verifies"  cargo run -q -p hux-crypto  --example crypto_walkthrough
run "Network walkthrough self-verifies" cargo run -q -p hux-network --example network_walkthrough

# Determinism: the same inputs must produce the same test outcome twice in a row. A flake here
# means something in the crypto path is not deterministic, which for an L1 is a fork risk.
run "Tests are deterministic (re-run)"  cargo test --all-targets --all-features --locked

# G0-T1 negative case: on aarch64, a deliberate avx2:: call must be REJECTED by the compiler.
# Skips itself on x86-64, where the backend exists and rejecting it would prove nothing.
run "Arch guard catches a regression"   ./scripts/check-arch-negative.sh

# Reproducible builds (G0-T2). Two full release builds, so it is opt-in: pass --full, or set
# HUX_VERIFY_FULL=1. CI always runs it.
if [[ "${1:-}" == "--full" || "${HUX_VERIFY_FULL:-}" == "1" ]]; then
  run "Builds are reproducible (G0-T2)" ./scripts/check-reproducible.sh
else
  printf '\n%s▸ Builds are reproducible (G0-T2)%s\n' "$BOLD" "$RESET"
  printf '  %sSKIPPED%s — two full release builds. Run with --full to include it.\n' "$YELLOW" "$RESET"
fi

# ── Summary ──────────────────────────────────────────────────────────────────────────────
printf '\n%s%s%s\n' "$BOLD" "$(printf '═%.0s' {1..72})" "$RESET"
printf '%sSummary%s\n' "$BOLD" "$RESET"
for i in "${!NAMES[@]}"; do
  if [[ "${RESULTS[$i]}" == "PASS" ]]; then
    printf '  %s✓%s  %s\n' "$GREEN" "$RESET" "${NAMES[$i]}"
  else
    printf '  %s✗%s  %s\n' "$RED" "$RESET" "${NAMES[$i]}"
  fi
done

printf '\n'
if [[ "$failures" -eq 0 ]]; then
  printf '  %sAll %d checks passed on %s.%s\n' "$GREEN" "${#NAMES[@]}" "$(uname -m)" "$RESET"
  printf '\n  %sLayer 0 is NOT complete.%s G0 (repo health) is closed; G1 (agility registry)\n' "$YELLOW" "$RESET"
  printf '  and G5 (transport) have not started — so this is one of three gates.\n'
  printf '  What you just verified is the primitive layer: signatures, KEM, derivation, domain\n'
  printf '  separation, signed envelopes — on THIS architecture only. Cross-architecture\n'
  printf '  agreement is proven by the CI matrix, not by this run.\n'
  printf '  Status: docs/20-completion/   Build order: docs/18-implementation-plan/\n'
else
  printf '  %s%d of %d checks FAILED.%s\n' "$RED" "$failures" "${#NAMES[@]}" "$RESET"
  printf '  Please open an issue with the transcript above:\n'
  printf '  https://github.com/ArunBabu98/huxplex/issues\n'
fi
printf '%s\n' "$(printf '═%.0s' {1..72})"

exit "$failures"
