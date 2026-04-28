#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Verify that every flag printed by `./pqc_readiness.py --help` is
# documented in README.md.  See the "README is part of the feature"
# section of CONTRIBUTING.md for the policy.
#
# Usage: scripts/check-readme-flags.sh
# Exit:  0 if every --help flag appears in README.md
#        1 if any --help flag is missing from README.md

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT="$REPO_ROOT/pqc_readiness.py"
README="$REPO_ROOT/README.md"

if [[ ! -x "$SCRIPT" ]]; then
  echo "error: $SCRIPT not found or not executable" >&2
  exit 2
fi
if [[ ! -f "$README" ]]; then
  echo "error: $README not found" >&2
  exit 2
fi

# Extract every long-form flag (`--foo`) printed by --help, dedup.
mapfile -t FLAGS < <(
  "$SCRIPT" --help \
    | grep -oE -- '--[a-z][a-z0-9-]+' \
    | sort -u
)

missing=()
for flag in "${FLAGS[@]}"; do
  if ! grep -qF -- "$flag" "$README"; then
    missing+=("$flag")
  fi
done

if (( ${#missing[@]} > 0 )); then
  echo "Flags in --help missing from README.md:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  echo >&2
  echo "Update README.md to mention each flag, then re-run:" >&2
  echo "  make check-readme" >&2
  exit 1
fi

echo "OK: every --help flag (${#FLAGS[@]}) appears in README.md."
