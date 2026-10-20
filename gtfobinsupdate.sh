#!/bin/bash
# Download a sorted, one-name-per-line list. Requires curl and jq.
# Usage: bash update_gtfobins.sh [output-file]
set -euo pipefail

out=${1:-gtfobins.txt}

for dep in curl jq; do
    if ! builtin type -P -- "$dep" >/dev/null 2>&1; then
        builtin printf '[-] Missing dependency: %s\n' "$dep" >&2
        exit 1
    fi
done

# Stage beside the destination so a failed update preserves the old list.
tmp=$(mktemp -- "${out}.tmp.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT

curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 60 \
    'https://gtfobins.org/api.json' |
    jq -er '
        .executables
        | if type == "object" and length > 0
          then keys[]
          else error("Expected a nonempty .executables object")
          end
    ' > "$tmp"

mv -f -- "$tmp" "$out"
builtin printf '[+] Saved GTFOBins names to %s\n' "$out"
