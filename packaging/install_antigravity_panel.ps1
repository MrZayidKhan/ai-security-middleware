$ErrorActionPreference = 'Stop'
try {
    $panel = Join-Path $PSScriptRoot 'antigravity-panel'
    $config = Join-Path $panel 'mcp_config.json'
    if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
        throw 'Run Setup.cmd first to prepare the panel configuration.'
    }
    . (Join-Path $PSScriptRoot 'find_agy.ps1')
    $agy = Find-AntigravityCli
    if (-not $agy) {
        throw 'Antigravity CLI not found. Install it from https://antigravity.google/docs/getting-started?tab=cli and reopen this launcher.'
    }
    & $agy plugin validate $panel --strict
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $agy plugin install $panel
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host 'Open Protected Send from the Plugins menu beside an Antigravity conversation.'
} catch {
    Write-Host "Panel setup failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
