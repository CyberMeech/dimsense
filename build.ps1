$ErrorActionPreference = "Stop"

Push-Location "$PSScriptRoot\frontend"
npm run build
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    exit $LASTEXITCODE
}
Pop-Location

cargo tauri build
exit $LASTEXITCODE
