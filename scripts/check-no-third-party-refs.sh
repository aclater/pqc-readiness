#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Reject third-party product references in the working tree.
# See CONTRIBUTING.md "Third-party product references" for policy.
#
# Usage: scripts/check-no-third-party-refs.sh
# Exit:  0 if clean, 1 if forbidden refs found, 2 on configuration error

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
PATTERN_FILE="$REPO_ROOT/scripts/forbidden-refs.txt"

if [[ ! -f "$PATTERN_FILE" ]]; then
  echo "error: $PATTERN_FILE not found" >&2
  exit 2
fi

cd "$REPO_ROOT"

EXCLUDE=(
  ':!scripts/forbidden-refs.txt'
  ':!scripts/check-no-third-party-refs.sh'
  ':!.github/workflows/no-third-party-refs.yml'
  ':!CONTRIBUTING.md'
)

if git grep -nIE -f "$PATTERN_FILE" -- "${EXCLUDE[@]}"; then
  echo
  echo "Found forbidden third-party product references." >&2
  echo "See CONTRIBUTING.md 'Third-party product references' for policy." >&2
  exit 1
fi

echo "OK: no third-party product references found."
