#!/usr/bin/env bash
# Refreshes ipv6-data.js from the three live IANA registries.
# Run from anywhere; paths below are resolved relative to the repo root.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

TOP_CSV="https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space-1.csv"
UNICAST_CSV="https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.csv"
SPECIAL_CSV="https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv"

TOP_PAGE="https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml"
UNICAST_PAGE="https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml"
SPECIAL_PAGE="https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Fetching IANA registry CSVs..."
curl -sf "$TOP_CSV" -o "$tmp/top.csv"
curl -sf "$UNICAST_CSV" -o "$tmp/unicast.csv"
curl -sf "$SPECIAL_CSV" -o "$tmp/special.csv"

last_updated() {
  curl -sf "$1" | grep -A1 'Last Updated' | tail -1 | sed -E 's/.*<dd>([^<]+)<\/dd>.*/\1/'
}
TOP_DATE="$(last_updated "$TOP_PAGE")"
UNICAST_DATE="$(last_updated "$UNICAST_PAGE")"
SPECIAL_DATE="$(last_updated "$SPECIAL_PAGE")"
echo "Registry 'Last Updated' dates: top=$TOP_DATE unicast=$UNICAST_DATE special=$SPECIAL_DATE"

node "$(dirname "${BASH_SOURCE[0]}")/build-ipv6-data.js" \
  "$tmp/top.csv" "$tmp/unicast.csv" "$tmp/special.csv" \
  "$TOP_DATE" "$UNICAST_DATE" "$SPECIAL_DATE" \
  > ipv6-data.js

echo "Wrote ipv6-data.js"
