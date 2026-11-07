$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot
New-Item -ItemType Directory -Force bin | Out-Null

$version = if ($env:VERSION) { $env:VERSION } else { '0.10.14-dev' }
$ldflags = "-s -w -X lineops-agent/internal/agentproto.Version=$version"

try {
    $env:GOOS = 'linux'
    $env:CGO_ENABLED = '0'
    foreach ($arch in @('amd64', 'arm64')) {
        $env:GOARCH = $arch
        Write-Host "Building lineops-agent-linux-$arch (version: $version) ..."
        go build -trimpath -ldflags="$ldflags" -o "bin/lineops-agent-linux-$arch" ./cmd/agent
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed for $arch"
        }
    }
    $checksums = foreach ($arch in @('amd64', 'arm64')) {
        $file = Get-Item "bin/lineops-agent-linux-$arch"
        $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($file.Name)"
    }
    [IO.File]::WriteAllLines((Join-Path $projectRoot 'bin/SHA256SUMS'), $checksums, (New-Object Text.UTF8Encoding $false))
    Write-Host "Build complete: bin/lineops-agent-linux-amd64, bin/lineops-agent-linux-arm64, bin/SHA256SUMS"
} finally {
    Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
}
