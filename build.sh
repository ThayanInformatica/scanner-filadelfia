#!/bin/sh
set -e
cd "$(dirname "$0")"
export PATH=/opt/homebrew/bin:$PATH
mkdir -p dist
if command -v goversioninfo >/dev/null 2>&1; then
  goversioninfo -64 -o resource_windows_amd64.syso versioninfo.json
elif [ -x "$HOME/go/bin/goversioninfo" ]; then
  "$HOME/go/bin/goversioninfo" -64 -o resource_windows_amd64.syso versioninfo.json
fi
API="${1:-${SCANNER_API:-}}"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-X main.apiPadrao=$API" -o dist/scanner.exe .
if [ -n "$API" ]; then
  echo "exe fala com $API quando o jogador informar um codigo"
else
  echo "exe sem servidor: roda 100% local"
fi
ls -la dist
