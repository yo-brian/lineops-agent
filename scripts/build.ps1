$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot
New-Item -ItemType Directory -Force bin | Out-Null

$targets = @(
    @{ GOOS = 'linux'; GOARCH = 'amd64' },
    @{ GOOS = 'linux'; GOARCH = 'arm64' },
    @{ GOOS = 'darwin'; GOARCH = 'arm64' },
    @{ GOOS = 'darwin'; GOARCH = 'amd64' }
)

try {
    $env:CGO_ENABLED = '0'
    foreach ($t in $targets) {
        $env:GOOS = $t.GOOS
        $env:GOARCH = $t.GOARCH
        $out = "bin/lineops-agent-$($t.GOOS)-$($t.GOARCH)"
        Write-Host "Building $out ..."
        go build -trimpath -ldflags="-s -w" -o $out ./cmd/agent
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed for $($t.GOOS)-$($t.GOARCH)"
        }
    }
    $checksums = foreach ($t in $targets) {
        $file = Get-Item "bin/lineops-agent-$($t.GOOS)-$($t.GOARCH)"
        $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($file.Name)"
    }
    [IO.File]::WriteAllLines((Join-Path $projectRoot 'bin/SHA256SUMS'), $checksums, (New-Object Text.UTF8Encoding $false))
    Write-Host "Build complete: linux (amd64/arm64) & darwin (arm64/amd64)"
} finally {
    Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
}
