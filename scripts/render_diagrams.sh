#!/usr/bin/env bash
# Re-render docs/diagrams/*.mmd to SVG. Requires node >= 18; Chromium is fetched by puppeteer
# unless PUPPETEER_EXECUTABLE_PATH points at an existing browser.
#
# If `npx` cannot download mermaid-cli (offline), install it once and put its bin on PATH:
#   npm install --prefix ~/.mmd @mermaid-js/mermaid-cli && export PATH=$PATH:~/.mmd/node_modules/.bin
# the script then uses the `mmdc` it finds.
set -euo pipefail
cd "$(dirname "$0")/.."
cfg=$(mktemp)
printf '{"args":["--no-sandbox","--disable-gpu"]%s}\n' \
  "${PUPPETEER_EXECUTABLE_PATH:+,\"executablePath\":\"$PUPPETEER_EXECUTABLE_PATH\"}" > "$cfg"
if command -v mmdc >/dev/null 2>&1; then
  mmd=(mmdc)
else
  mmd=(npx --yes @mermaid-js/mermaid-cli)
fi
for f in docs/diagrams/*.mmd; do
  "${mmd[@]}" -p "$cfg" -c docs/diagrams/mermaid.config.json -i "$f" -o "${f%.mmd}.svg" -b transparent
done
rm -f "$cfg"
