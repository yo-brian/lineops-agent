#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p bin

VERSION_FLAG=""
if [[ -n "${VERSION:-}" ]]; then
  VERSION_FLAG="-X lineops-agent/internal/agentproto.Version=${VERSION}"
fi

for os in linux darwin; do
  for arch in amd64 arm64; do
    echo "Building lineops-agent-${os}-${arch} ..."
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w ${VERSION_FLAG}" -o "bin/lineops-agent-${os}-${arch}" ./cmd/agent
  done
done

(cd bin && sha256sum lineops-agent-linux-amd64 lineops-agent-linux-arm64 lineops-agent-darwin-arm64 lineops-agent-darwin-amd64 > SHA256SUMS)
echo "Build complete: linux (amd64/arm64) & darwin (arm64/amd64)"
