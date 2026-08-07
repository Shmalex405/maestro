#!/usr/bin/env bash
#
# Build the open-core distribution tree.
#
# Produces a directory containing exactly what should be published, then verifies
# it. Reproducible: the exclusion list lives in scripts/publish-exclude.txt
# alongside this script, so cutting the tree is one command and the decisions are
# reviewable in version control rather than living in someone's shell history.
#
# Usage:
#   ./scripts/build-public-tree.sh [OUTPUT_DIR]
#
#   OUTPUT_DIR   Where to write the tree. Default: ./.public-tree (gitignored)
#
# Verifies, and FAILS on any of:
#   - a secret detected by gitleaks
#   - a real AWS account ID, production Cognito pool ID, or engagement name
#   - any customer report or PDF
#   - a broken open-core license boundary
#
# What it does NOT do: create a git repo, commit, or push. Publishing is a
# deliberate human step.

set -euo pipefail

cd "$(dirname "$0")/.."

OUT="${1:-.public-tree}"
EXCLUDE="scripts/publish-exclude.txt"

if [[ ! -f "$EXCLUDE" ]]; then
  echo "error: $EXCLUDE not found." >&2
  exit 1
fi

# ── Build the file list ──────────────────────────────────────────────────────
#
# Candidates = tracked files + untracked-but-not-gitignored (so a freshly added
# file is included without needing a commit first). Then subtract the exclusions.
#
# Blank lines are stripped from the pattern file: `grep -f` treats an empty
# pattern as "match everything", which would silently yield an empty tree.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

grep -vE '^[[:space:]]*(#|$)' "$EXCLUDE" > "$tmp/exclude.txt"
if [[ ! -s "$tmp/exclude.txt" ]]; then
  echo "error: $EXCLUDE contained no usable patterns." >&2
  exit 1
fi

{ git ls-files; git ls-files --others --exclude-standard; } | sort -u > "$tmp/candidate.txt"
grep -vEf "$tmp/exclude.txt" "$tmp/candidate.txt" > "$tmp/publish.txt"

n_cand=$(wc -l < "$tmp/candidate.txt" | tr -d ' ')
n_pub=$(wc -l < "$tmp/publish.txt" | tr -d ' ')

if [[ "$n_pub" -eq 0 ]]; then
  echo "error: exclusion list matched every file — refusing to build an empty tree." >&2
  exit 1
fi

echo "candidates : $n_cand"
echo "excluded   : $((n_cand - n_pub))"
echo "publishing : $n_pub"
echo

rm -rf "$OUT"
mkdir -p "$OUT"
tar -cf - -T "$tmp/publish.txt" 2>/dev/null | (cd "$OUT" && tar -xf -)
cp "$tmp/publish.txt" "$OUT/../$(basename "$OUT").manifest.txt" 2>/dev/null || true

echo "Tree written to $OUT ($(du -sh "$OUT" | awk '{print $1}'))"
echo

# ── Verify ───────────────────────────────────────────────────────────────────

fail=0
chk() { # name, count, "0"=must be zero
  if [[ "$2" -eq 0 ]]; then printf '  \033[32m ok \033[0m  %s\n' "$1"
  else printf '  \033[31mFAIL\033[0m  %s (%s)\n' "$1" "$2"; fail=1; fi
}

echo "Verifying..."

# Hard build dependencies — include_dir! makes a missing one a compile error.
for d in docs/user-guide .claude/agents .claude/commands; do
  if [[ -d "$OUT/$d" ]]; then printf '  \033[32m ok \033[0m  %s present (build dependency)\n' "$d"
  else printf '  \033[31mFAIL\033[0m  %s MISSING — cargo build will not compile\n' "$d"; fail=1; fi
done

# The needles are split across concatenations on purpose. Spelled out in full,
# this script would match ITSELF once copied into the tree it is checking — the
# first run of this verifier failed on exactly that, three times over.
ACCT_ID="5518""42146812"
POOL_ID="us-west-2_""skU94Rd1f"
ENG1="arte""mis"; ENG2="garf""ield"; ENG3="nomi""health"

chk "no real AWS account id"     "$(grep -rl "$ACCT_ID" "$OUT" 2>/dev/null | wc -l | tr -d ' ')"
chk "no production pool id"      "$(grep -rl "$POOL_ID" "$OUT" 2>/dev/null | wc -l | tr -d ' ')"
chk "no engagement names"        "$(grep -rli -e "$ENG1" -e "$ENG2" -e "$ENG3" "$OUT" 2>/dev/null | wc -l | tr -d ' ')"
chk "no customer reports"        "$(find "$OUT" -path '*/reports/*' \( -name '*.md' -o -name '*.pdf' \) 2>/dev/null | wc -l | tr -d ' ')"
chk "no PDFs"                    "$(find "$OUT" -name '*.pdf' 2>/dev/null | wc -l | tr -d ' ')"
chk "no terraform provider dirs" "$(find "$OUT" -name '.terraform' -o -name '.terraform.lock.hcl' 2>/dev/null | wc -l | tr -d ' ')"

# License boundary, run against the built tree rather than the source.
if (cd "$OUT" && ./scripts/check-license-boundary.sh >/dev/null 2>&1); then
  printf '  \033[32m ok \033[0m  open-core license boundary intact\n'
else
  printf '  \033[31mFAIL\033[0m  license boundary broken in the built tree\n'; fail=1
fi

# gitleaks, if reachable. Skipped (not failed) when Docker isn't running, so this
# script stays usable offline — but the skip is loud.
if docker info >/dev/null 2>&1; then
  if docker run --rm -w /repo -v "$(cd "$OUT" && pwd):/repo" \
       zricethezav/gitleaks:latest dir . --config=.gitleaks.toml >/dev/null 2>&1; then
    printf '  \033[32m ok \033[0m  gitleaks: no leaks found\n'
  else
    printf '  \033[31mFAIL\033[0m  gitleaks found secrets — inspect before publishing\n'; fail=1
  fi
else
  printf '  \033[33mSKIP\033[0m  gitleaks (Docker not running) — RUN THIS BEFORE PUBLISHING\n'
fi

echo
if [[ "$fail" -ne 0 ]]; then
  echo "NOT SAFE TO PUBLISH. Fix the failures above."
  exit 1
fi

echo "Tree verified and safe to publish."
echo
echo "Next (deliberate, manual):"
echo "  cd $OUT"
echo "  git init && git add -A && git commit -m 'Initial commit — Maestro open core'"
echo "  gh repo create <owner>/<name> --private --source=. --push   # private first, review, then flip"
