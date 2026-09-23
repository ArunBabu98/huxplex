#!/usr/bin/env bash
# G0-8 (negative half) — the deliberate-regression check for G0-T1.
#
#   docs/18-implementation-plan/01-g0-repository-health.md § G0-5
#   "a deliberate `avx2::` call must *fail* the aarch64 job. A matrix that only ever passes
#    does not prove it would catch the regression it exists for."
#
# This injects the exact break that once shipped — an unconditional `mlkem768::avx2::*` call —
# into a throwaway copy of the tree, and asserts the compiler REJECTS it. If the injection
# compiles, the safety net is not there, and this script fails.
#
# Runs only where the AVX2 backend genuinely does not exist (i.e. not x86-64). On x86-64 with
# the `simd256` feature the path is real and compiling it proves nothing, so the check skips.
#
# Companion: scripts/check-arch-portability.sh proves nobody wrote the call; this proves the
# build would notice if they did. Neither replaces the other.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"

ARCH="$(uname -m)"
if [[ "$ARCH" == "x86_64" || "$ARCH" == "amd64" ]]; then
  echo "SKIP  host is $ARCH — the avx2 backend exists here, so rejecting it proves nothing."
  echo "      This check is meaningful on aarch64/arm64, where the module must not resolve."
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "G0-T1 negative case"
echo "  host arch  : $ARCH"
echo "  staging at : $TMP"

# Copy the WORKING TREE (not HEAD) so an uncommitted regression is caught too.
tar -cf - --exclude='./target' --exclude='./.git' . | (cd "$TMP" && tar -xf -)

TARGET="crates/hux-crypto/src/kem/ml_kem.rs"

# The injection target must already exist. `cat >>` would otherwise happily CREATE it, the file
# would not be part of any module, the build would succeed, and this script would report "the
# injected call COMPILED" — blaming the guarantee for what is really a stale path after a
# refactor. Fail with the true cause instead.
if [[ ! -f "$TMP/$TARGET" ]]; then
  echo "FAIL  injection target $TARGET does not exist."
  echo
  echo "      The module was probably moved or renamed. Update TARGET in this script to wherever"
  echo "      libcrux_ml_kem is now called; scripts/check-primitive-encapsulation.sh names the"
  echo "      single file permitted to do so."
  exit 1
fi

# The injection: the original G0 break, verbatim in shape.
cat >> "$TMP/$TARGET" <<'RUST'

// Injected by scripts/check-arch-negative.sh. MUST NOT COMPILE on aarch64.
pub fn g0_negative_case_probe(randomness: [u8; 64]) -> [u8; EK_SIZE] {
    let keypair = mlkem768::avx2::generate_key_pair(randomness);
    let (_dk, ek) = keypair.into_parts();
    *ek.as_slice()
}
RUST

echo "  injected   : mlkem768::avx2::generate_key_pair in $TARGET"
echo

# Separate target dir: keeps this check's artifacts out of the main build's fingerprints.
export CARGO_TARGET_DIR="$REPO/target/arch-negative"

set +e
out="$(cd "$TMP" && cargo check -p hux-crypto --all-features --locked 2>&1)"
status=$?
set -e

# CI sets CARGO_TERM_COLOR=always, which embeds ANSI escapes inside `error[E0433]:`. Strip them
# before matching or reporting, or the evidence below prints blank on exactly the runs that
# matter most.
out="$(sed -E $'s/\x1b\\[[0-9;]*[a-zA-Z]//g' <<< "$out")"

if [[ "$status" -eq 0 ]]; then
  echo "FAIL  the injected avx2:: call COMPILED on $ARCH."
  echo
  echo "      That means the architecture-portability guarantee is not being enforced by the"
  echo "      compiler here, and the CI matrix would not catch a reintroduction of the original"
  echo "      G0 break. Investigate before trusting any green matrix run."
  exit 1
fi

# A non-zero exit is necessary but not sufficient: an unrelated compile error would otherwise
# be read as success. Require the failure to actually be about the backend path.
if ! grep -qE 'avx2|E0433|E0425' <<< "$out"; then
  echo "FAIL  the build failed, but not because of the avx2:: call — so this check proved nothing."
  echo
  echo "      Compiler output:"
  sed 's/^/      /' <<< "$out" | tail -30
  exit 1
fi

echo "PASS  the injected avx2:: call was rejected by the compiler on $ARCH."
echo
evidence="$(grep -E 'error(\[E[0-9]+\])?:' <<< "$out" | head -6)"
if [[ -n "$evidence" ]]; then
  sed 's/^/      /' <<< "$evidence"
else
  # Should not happen — the guard above already required avx2/E0433 in the output — but never
  # print an empty evidence block, which would read as a check that proved nothing.
  echo "      (compiler reported a failure mentioning avx2/E0433; see the full log)"
fi
echo
echo "      The regression that broke every ARM build in 2026-09 would be caught here."
