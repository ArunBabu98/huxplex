#!/usr/bin/env bash
# G1 · C4 — the suite registry must be the ONLY path to a primitive.
#
#   docs/18-implementation-plan/02-g1-crypto-core.md, task C4:
#   "Traits Signer/Verifier/Kem/Hasher; no direct call to a named scheme outside the registry.
#    Acceptance: a CI grep (or a lint) proving no `libcrux_ml_dsa::` path exists outside
#    sig/ml_dsa.rs."
#
# Why this is mechanical and not a review convention: the whole agility thesis is that no layer
# above the registry knows which algorithm it is using. One direct call is enough to falsify it,
# and it will be invisible in review precisely because it looks like ordinary working code.
#
# Companion to scripts/check-arch-portability.sh, which enforces the other "never call this
# directly" rule (architecture-specific backends, G0).
set -euo pipefail

cd "$(dirname "$0")/.."

# vendor crate -> the single file allowed to name it
declare -a RULES=(
  "libcrux_ml_dsa|crates/hux-crypto/src/sig/ml_dsa.rs"
  "libcrux_ml_kem|crates/hux-crypto/src/kem/ml_kem.rs"
)

fail=0

for rule in "${RULES[@]}"; do
  crate="${rule%%|*}"
  allowed="${rule##*|}"

  if [[ ! -f "$allowed" ]]; then
    echo "FAIL  the designated home for '$crate' does not exist: $allowed"
    fail=1
    continue
  fi

  # Search Rust sources only. Comments are exempt so the rule can be explained where it matters
  # (the modules themselves name the crate in their doc comments).
  offenders="$(
    find crates -type f -name '*.rs' \
      \( -path '*/src/*' -o -path '*/tests/*' -o -path '*/examples/*' \) \
      ! -path "./$allowed" ! -path "$allowed" \
      -print0 2>/dev/null \
      | xargs -0 grep -nE "(^|[^A-Za-z0-9_])${crate}([^A-Za-z0-9_]|$)" 2>/dev/null \
      | grep -vE ':[[:space:]]*//' || true
  )"

  if [[ -n "$offenders" ]]; then
    while IFS= read -r line; do
      echo "FAIL  $line"
    done <<< "$offenders"
    fail=1
  else
    echo "ok    $crate is confined to $allowed"
  fi
done

echo
if [[ "$fail" -ne 0 ]]; then
  cat <<'MSG'
A vendor cryptographic crate is named outside its designated module.

Reach primitives through the suite registry instead — it resolves (role, suite version) to a
scheme, and the trait turns that into an operation:

  wrong:  libcrux_ml_dsa::ml_dsa_44::sign(&sk, msg, ctx, rnd)
  right:  let scheme = AlgoSuite::new(SigRole::Transaction, SuiteVersion::V1)
                           .signature_scheme()?;
          traits::implementation(scheme)?.sign(&sk, msg, ctx, &rnd)?

A direct call hard-codes an algorithm into a call site that will outlive the decision to use it.
See docs/18-implementation-plan/02-g1-crypto-core.md task C4 and ADR-0018.
MSG
  exit 1
fi

echo "Primitive encapsulation OK — the registry is the only path to a scheme."
