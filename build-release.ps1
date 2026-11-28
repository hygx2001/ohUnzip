$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    $toml = Get-Content (Join-Path $root "Cargo.toml") -Raw
    if ($toml -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
        throw "Failed to parse version from Cargo.toml"
    }
    $version = $Matches[1]

    Write-Host "Building OhUnzip v$version (release)..." -ForegroundColor Cyan
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $srcExe = Join-Path $root "target\release\oh-unzip.exe"
    $dstExe = Join-Path $root "target\release\OhUnzip-v$version.exe"
    Copy-Item -Path $srcExe -Destination $dstExe -Force

    $item = Get-Item $dstExe
    Write-Host ("Done: {0} ({1:N0} bytes)" -f $item.FullName, $item.Length) -ForegroundColor Green
}
finally {
    Pop-Location
}
