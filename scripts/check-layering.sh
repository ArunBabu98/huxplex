#!/usr/bin/env bash
# Enforces the downward-only crate dependency rule.
#
#   docs/10-development/repository-structure.md § Dependency rule (enforced)
#   "Crates depend downward only (no cycles) … a cycle is a build failure."
#
# Layer 0 today:  hux-network → hux-crypto → (nothing in-workspace)
#
# Add a row to LAYERS as each new crate lands. Lower index = lower layer.
# A crate may depend on any crate with a STRICTLY LOWER index, and on nothing else in-workspace.
set -euo pipefail

cd "$(dirname "$0")/.."

# Ordered low → high.
LAYERS=(
  hux-crypto
  hux-network
)

fail=0

layer_index() {
  local name="$1" i=0
  for c in "${LAYERS[@]}"; do
    if [[ "$c" == "$name" ]]; then echo "$i"; return 0; fi
    i=$((i + 1))
  done
  echo "-1"
}

for crate_toml in crates/*/Cargo.toml; do
  crate_dir="$(dirname "$crate_toml")"
  crate_name="$(basename "$crate_dir")"
  idx="$(layer_index "$crate_name")"

  if [[ "$idx" == "-1" ]]; then
    echo "FAIL  $crate_name is not listed in LAYERS in $0 — add it at its layer."
    fail=1
    continue
  fi

  # In-workspace dependencies are the ones named hux-*.
  deps="$(grep -oE '^hux-[a-z0-9-]+' "$crate_toml" | sort -u || true)"

  for dep in $deps; do
    [[ "$dep" == "$crate_name" ]] && continue
    dep_idx="$(layer_index "$dep")"
    if [[ "$dep_idx" == "-1" ]]; then
      echo "FAIL  $crate_name depends on unknown workspace crate '$dep'."
      fail=1
    elif [[ "$dep_idx" -ge "$idx" ]]; then
      echo "FAIL  $crate_name (layer $idx) depends on $dep (layer $dep_idx) — not downward."
      fail=1
    else
      echo "ok    $crate_name -> $dep"
    fi
  done
done

if [[ "$fail" -ne 0 ]]; then
  echo
  echo "Crate layering violated. See docs/10-development/repository-structure.md."
  exit 1
fi

echo
echo "Crate layering OK (downward-only)."
