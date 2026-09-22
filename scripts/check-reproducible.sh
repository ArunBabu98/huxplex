#!/usr/bin/env bash
# G0-T2 — reproducible builds.
#
#   ./scripts/check-reproducible.sh
#
# Builds the workspace twice from two independent clean copies of the source, at the same
# canonical build path, and compares the artifacts byte for byte.
#
# Why this matters: a binary nobody can independently reproduce is a binary everyone has to
# take on trust. Principle 15 — "Reproducibility and openness. Neutrality requires
# verifiability." For a chain meant to be neutral, that is not a nice-to-have.
#
# ── The recipe (keep in sync with docs/10-development/ci-cd.md) ───────────────────────────
#   --locked                pin every dependency to the committed Cargo.lock
#   SOURCE_DATE_EPOCH       fix any embedded timestamp
#   --remap-path-prefix     erase the source and registry paths from debug info
#   a canonical build path  see the note below — this one is load-bearing
#
# ── Why a canonical build path is required ────────────────────────────────────────────────
# `--remap-path-prefix` takes the absolute source path as its argument, so building at two
# different paths produces two different RUSTFLAGS strings. RUSTFLAGS feeds rustc's `-C
# metadata` hash, which feeds symbol names, so the artifacts differ even though the *source*
# is identical. Erasing the path from the output does not erase it from the flag that erased
# it.
#
# The standard answer — used by Debian, Nix and others — is to agree on one canonical build
# path. Huxplex's is `/tmp/hux-reproducible-build`, set below and documented in ci-cd.md. Two
# builders following the recipe get identical bytes; a builder who ignores it does not, and
# that is a property of Rust, not a bug here.
#
# ⚠️ This baseline is established on a PURE RUST tree. `aws-lc-rs` arrives at G5 and compiles C
# and assembly, at which point the C toolchain becomes part of the recipe and this check MUST
# be re-run. If it cannot be made to pass then, that is a stop condition, not something to
# paper over — ADR-0019 condition 3, and 18-implementation-plan/04-sequencing-and-risks.md R4.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"

CANONICAL="${HUX_BUILD_PATH:-/tmp/hux-reproducible-build}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$CANONICAL"' EXIT

echo "Reproducible-build check"
echo "  source         : $REPO"
echo "  canonical path : $CANONICAL"
echo "  rustc          : $(rustc --version)"
echo

# Two independent clean copies of the tracked source.
stage_copy() {
  local dest="$1"
  mkdir -p "$dest"
  if git diff --quiet && git diff --cached --quiet; then
    git archive HEAD | tar -x -C "$dest"
  else
    # Uncommitted work — check what is actually in the tree, not what is committed.
    rsync -a --exclude target --exclude .git "$REPO"/ "$dest"/
  fi
}
stage_copy "$STAGE/copy-a"
stage_copy "$STAGE/copy-b"

export SOURCE_DATE_EPOCH=1600000000
CARGO_HOME_DEFAULT="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="--remap-path-prefix=$CANONICAL=/huxplex --remap-path-prefix=$CARGO_HOME_DEFAULT=/cargo"

build_at_canonical() {
  local from="$1"
  rm -rf "$CANONICAL"
  cp -R "$from" "$CANONICAL"
  (cd "$CANONICAL" && cargo build --release --locked --quiet)
}

hash_artifacts() {
  find "$CANONICAL/target/release" -maxdepth 1 -name 'libhux_*.rlib' -print0 \
    | sort -z \
    | xargs -0 -I{} sh -c 'printf "%s  %s\n" "$(basename "$1")" "$(shasum -a 256 < "$1" | cut -d" " -f1)"' _ {}
}

echo "Building copy A at the canonical path…"
build_at_canonical "$STAGE/copy-a"
HA="$(hash_artifacts)"

echo "Building copy B at the canonical path…"
build_at_canonical "$STAGE/copy-b"
HB="$(hash_artifacts)"
echo

echo "Build A artifacts:"; echo "$HA" | sed 's/^/  /'
echo "Build B artifacts:"; echo "$HB" | sed 's/^/  /'
echo

if [[ -z "$HA" ]]; then
  echo "FAIL  no artifacts found — did the build produce anything?"
  exit 1
fi

if [[ "$HA" == "$HB" ]]; then
  echo "PASS  two independent clean checkouts produced byte-identical artifacts."
  exit 0
fi

echo "FAIL  builds differ. The artifacts are not reproducible."
echo
diff <(echo "$HA") <(echo "$HB") || true
echo
echo "Common causes: an absolute path leaking into debug info (extend --remap-path-prefix),"
echo "an embedded timestamp, a dependency resolving differently (check --locked), or a"
echo "non-deterministic build script in a dependency."
exit 1
