#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p bin

for arch in amd64 arm64; do
  echo "Building lineops-agent-linux-$arch ..."
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags="-s -w" -o "bin/lineops-agent-linux-$arch" ./cmd/agent
done

(cd bin && sha256sum lineops-agent-linux-amd64 lineops-agent-linux-arm64 > SHA256SUMS)
echo "Build complete: bin/lineops-agent-linux-amd64, bin/lineops-agent-linux-arm64"
