#!/usr/bin/env bash
# G0-8 (static half) — no architecture-specific cryptographic backend paths in source.
#
#   docs/16-action-plan.md § G0 standing rule
#   "never call an architecture-specific backend path (`mlkem768::avx2::*`, `::neon::*`)
#    directly. Always use the top-level dispatching entry point."
#
# Why this is a gate and not a style preference: AVX2 exists only on x86-64. The repository
# once called `mlkem768::avx2::*` unconditionally, which broke every ARM build — and a PQ chain
# whose crypto builds on only one ISA cannot have a diverse validator set. Architecture
# portability is a decentralization property here.
#
# This is the cheap half of G0-8: it proves nobody *wrote* the call. The expensive half,
# scripts/check-arch-negative.sh, proves CI would *notice* if they did. Keep both.
#
# Scope: Rust sources under crates/*/src and crates/*/tests. Cargo.toml is exempt on purpose —
# `simd256` / `simd128` there are target-gated feature selections, which is exactly how a
# backend SHOULD be chosen. Whole-line comments are exempt so the reasoning above (and the note
# in kem.rs) can name the forbidden paths without tripping the check.
set -euo pipefail

cd "$(dirname "$0")/.."

# Backend module paths that must never be called directly.
FORBIDDEN='::(avx2|neon|simd256|simd128|portable)::'

fail=0
scanned=0

while IFS= read -r file; do
  scanned=$((scanned + 1))
  # Match, then drop whole-line comments (`//`, `//!`, `///`) from the hits. A backend path in
  # a *trailing* comment is still reported — deliberately, since it is almost always a stale
  # instruction that someone will eventually follow.
  hits="$(grep -nE "$FORBIDDEN" "$file" | grep -vE '^[0-9]+:[[:space:]]*//' || true)"
  if [[ -n "$hits" ]]; then
    while IFS= read -r line; do
      echo "FAIL  $file:$line"
    done <<< "$hits"
    fail=1
  fi
done < <(find crates -type f -name '*.rs' \( -path '*/src/*' -o -path '*/tests/*' \) | sort)

echo
if [[ "$fail" -ne 0 ]]; then
  cat <<'MSG'
Architecture-specific backend path called directly.

Use the top-level dispatching entry point instead — libcrux's multiplexing layer detects CPU
capability at runtime and falls back to portable. All backends are output-identical, so
dispatching costs nothing, while hardcoding one excludes an entire architecture from the network.

  wrong:  libcrux_ml_kem::mlkem768::avx2::generate_key_pair(seed)
  right:  libcrux_ml_kem::mlkem768::generate_key_pair(seed)

See docs/16-action-plan.md § G0 and crates/hux-crypto/src/kem.rs.
MSG
  exit 1
fi

echo "Architecture portability OK — $scanned Rust files scanned, no direct backend paths."
