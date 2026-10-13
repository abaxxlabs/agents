#!/usr/bin/env bash
set -euo pipefail

# Print the CHANGELOG.md section for one version, without its heading.
# Usage: extract-changelog.sh <version> [changelog-path]
VERSION="${1:-}"
CHANGELOG="${2:-CHANGELOG.md}"
if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version> [changelog-path]" >&2
  exit 1
fi

# Escape regex metacharacters so 0.38.1 cannot match 0x38y1.
VERSION_PATTERN=$(printf '%s' "$VERSION" | sed 's/[][\.*^$+?(){}|/]/\\&/g')

# Capture lines under the target heading until the next version heading,
# then strip leading and trailing blank lines.
awk -v ver="$VERSION_PATTERN" '
  /^## \[[^]]+\]/ {
    if (capture) exit
    if ($0 ~ "^## \\[" ver "\\]") {
      capture = 1
      next
    }
  }
  capture {
    lines[i++] = $0
  }
  END {
    while (i > 0 && lines[i-1] ~ /^[ \t]*$/) {
      i--
    }
    start = 0
    while (start < i && lines[start] ~ /^[ \t]*$/) {
      start++
    }
    for (j = start; j < i; j++) {
      print lines[j]
    }
  }
' "$CHANGELOG"
