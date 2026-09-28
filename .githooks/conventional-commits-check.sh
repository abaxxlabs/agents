#!/usr/bin/env bash
# conventional-commits-check.sh — shipped by hygiene-kit.
# Single source of truth for the Conventional Commits rule, shared by the
# commit-msg git hook (best-effort, local) and the CI commit-lint job (hard gate).
#
# Usage:
#   conventional-commits-check.sh --file <commit-msg-file>   # validate a message file (hook)
#   conventional-commits-check.sh --subject "<subject line>" # validate one subject (CI loop)
#
# Exits 0 when the subject is valid, or is a merge/revert/autosquash commit.
# Exits 1 with an explanatory message when the subject is not Conventional Commits.
set -euo pipefail

# Fixed, global type set across all Abaxx repos. Keep in sync with conventions.
TYPES='feat|fix|perf|docs|chore|test|ci'
pattern="^(${TYPES})(\([a-z0-9._/-]+\))?(!)?: .+"

usage() {
  echo "usage: $(basename "$0") --file <commit-msg-file> | --subject <line>" >&2
  exit 2
}

case "${1:-}" in
  --file)
    [[ -n "${2:-}" && -f "$2" ]] || usage
    # Subject = first non-empty, non-comment line.
    subject="$(grep -vE '^[[:space:]]*#' "$2" | grep -vE '^[[:space:]]*$' | head -n1 || true)"
    ;;
  --subject)
    [[ $# -ge 2 ]] || usage
    subject="$2"
    ;;
  *)
    usage
    ;;
esac

# Allow merge / revert / autosquash commits through untouched.
case "$subject" in
  Merge\ *|Revert\ *|fixup!\ *|squash!\ *|amend!\ *) exit 0 ;;
esac

if [[ "$subject" =~ $pattern ]]; then
  exit 0
fi

cat >&2 <<EOF
✗ Commit message does not follow Conventional Commits.

  Subject:  ${subject:-(empty)}

  Format:   <type>(<optional scope>)<optional !>: <description>
  Types:    feat, fix, perf, docs, chore, test, ci
  Breaking: add ! after the type/scope, or a "BREAKING CHANGE:" footer.

  Examples:
    feat: add OIDC provider
    fix(auth): reject expired tokens
    feat(api)!: drop v1 endpoints
EOF
exit 1
