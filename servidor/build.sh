#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/scanner-auth .
echo "gerado: $(pwd)/dist/scanner-auth"
