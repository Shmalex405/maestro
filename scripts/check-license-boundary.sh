#!/usr/bin/env bash
#
# Verifies the open-core license boundary is intact.
#
# The COMMERCIAL-COMPONENTS manifest is the authoritative list of proprietary
# paths. This script checks three invariants that a careless refactor could
# silently break:
#
#   1. Every path listed in the manifest still exists. A renamed directory that
#      drops off the manifest is a path that quietly became Apache-2.0.
#   2. Every listed DIRECTORY carries its own LICENSE marker, so a file that
#      travels out of the repo still says what it is.
#   3. The root LICENSE, LICENSE-COMMERCIAL, and NOTICE are all present.
#
# Exits non-zero with a specific message on any violation. Run from repo root.

set -euo pipefail

cd "$(dirname "$0")/.."

MANIFEST="COMMERCIAL-COMPONENTS"
fail=0

err() {
  printf '  \033[31mFAIL\033[0m  %s\n' "$1"
  fail=1
}
ok() {
  printf '  \033[32m ok \033[0m  %s\n' "$1"
}

echo "Checking open-core license boundary..."
echo

# --- Invariant 3: root license files present -------------------------------
for f in LICENSE LICENSE-COMMERCIAL NOTICE "$MANIFEST"; do
  if [[ -f "$f" ]]; then
    ok "$f present"
  else
    err "$f is missing"
  fi
done

if [[ ! -f "$MANIFEST" ]]; then
  echo
  echo "Cannot continue without $MANIFEST."
  exit 1
fi

# The root LICENSE must actually be Apache-2.0, not the old proprietary text.
if grep -q "Apache License" LICENSE; then
  ok "LICENSE is Apache-2.0"
else
  err "LICENSE does not look like Apache-2.0"
fi

# ...and it must still carry the carve-out notice, or readers will assume the
# whole tree is Apache-licensed.
if grep -q "COMMERCIAL-COMPONENTS" LICENSE; then
  ok "LICENSE points at the commercial manifest"
else
  err "LICENSE is missing the COMMERCIAL-COMPONENTS carve-out notice"
fi

echo

# --- Invariants 1 and 2: manifest paths ------------------------------------
listed=0
while IFS= read -r line; do
  # Strip comments and blank lines.
  line="${line%%#*}"
  line="$(printf '%s' "$line" | tr -d '[:space:]')"
  [[ -z "$line" ]] && continue

  listed=$((listed + 1))

  if [[ "$line" == */ ]]; then
    dir="${line%/}"
    if [[ ! -d "$dir" ]]; then
      err "$line listed in manifest but directory does not exist"
      continue
    fi
    if [[ ! -f "$dir/LICENSE" ]]; then
      err "$line has no LICENSE marker (add one; see LICENSE-COMMERCIAL)"
      continue
    fi
    if ! grep -q "PROPRIETARY" "$dir/LICENSE"; then
      err "$dir/LICENSE exists but does not declare the contents proprietary"
      continue
    fi
    ok "$line (directory + marker)"
  else
    if [[ ! -f "$line" ]]; then
      err "$line listed in manifest but file does not exist"
      continue
    fi
    ok "$line (file)"
  fi
done < "$MANIFEST"

echo
if [[ "$listed" -eq 0 ]]; then
  err "manifest lists no paths — did it get truncated?"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "License boundary is BROKEN. See failures above."
  exit 1
fi

echo "License boundary intact ($listed paths listed)."
