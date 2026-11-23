param(
    [ValidateSet('codex', 'antigravity')]
    [string]$Agent,
    [string]$Workspace,
    [switch]$Acp,
    [switch]$WorkspaceHooks
)

$ErrorActionPreference = 'Stop'

try {
    $configureHooks = $WorkspaceHooks -or $Agent -or $Workspace
    if ($Acp -and $configureHooks) {
        throw 'Choose ACP setup or workspace hooks.'
    }
    if ($configureHooks -and -not $Agent) {
        Write-Host '1. Codex'
        Write-Host '2. Antigravity'
        switch (Read-Host 'Choose your agent (1 or 2)') {
            '1' { $Agent = 'codex' }
            '2' { $Agent = 'antigravity' }
            default { throw 'Choose 1 for Codex or 2 for Antigravity.' }
        }
    }
    if ($configureHooks -and -not $Workspace) {
        $Workspace = (Read-Host 'Enter the full path to the workspace to protect').Trim().Trim('"')
    }
    if ($configureHooks -and (-not $Workspace -or -not (Test-Path -LiteralPath $Workspace -PathType Container))) {
        throw 'The selected workspace must be an existing folder.'
    }
    if ($configureHooks) {
        $Workspace = (Resolve-Path -LiteralPath $Workspace).Path
    }
    $model = Join-Path $PSScriptRoot 'model'
    $wheels = Join-Path $PSScriptRoot 'wheels'
    foreach ($file in 'model_quantized.onnx', 'tokenizer.json', 'config.json', 'advisory_profile.json') {
        if (-not (Test-Path -LiteralPath (Join-Path $model $file) -PathType Leaf)) {
            throw "Missing model file $file. Extract the entire setup ZIP before running Setup.cmd."
        }
    }
    if (-not (Test-Path -LiteralPath $wheels -PathType Container)) {
        throw 'Extract the entire setup ZIP before running Setup.cmd.'
    }
    $venv = Join-Path $PSScriptRoot '.venv'
    $runtime = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'python-version.txt') -Raw).Trim()
    if ($runtime -notmatch '^3\.(13|14)$') { throw 'Invalid bundled Python version.' }
    $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($pythonCommand -and (& $pythonCommand.Source -c "import sys; print('.'.join(map(str, sys.version_info[:2])))") -eq $runtime) {
        & $pythonCommand.Source -m venv $venv
    } elseif (Get-Command py.exe -ErrorAction SilentlyContinue) {
        & py.exe "-$runtime" -m venv $venv
    } else {
        throw "This setup needs Windows Python $runtime."
    }
    if ($LASTEXITCODE -ne 0) { throw "Could not create the Python $runtime environment." }
    $python = Join-Path $venv 'Scripts\python.exe'
    & $python -m pip --isolated install --disable-pip-version-check --no-index --find-links $wheels 'ai-security-middleware[gateway]' onnxruntime tokenizers numpy
    if ($LASTEXITCODE -ne 0) { throw 'Offline dependency installation failed. Check Python and CPU compatibility.' }
    & $python -c "import sys; from pathlib import Path; from security_middleware.horizon_detector import HorizonDetector; result = HorizonDetector.from_advisory_profile(Path(sys.argv[1])).detect('Summarize these notes.'); sys.exit(result.risk == 'unavailable')" $model
    if ($LASTEXITCODE -ne 0) { throw 'The offline detector failed its startup check.' }
    $auditDb = Join-Path $PSScriptRoot 'runtime_data\security_events.db'
    & $python -c "import sys; from pathlib import Path; from security_middleware.audit_log import initialize_audit_database; path = Path(sys.argv[1]); path.parent.mkdir(exist_ok=True); initialize_audit_database(path)" $auditDb
    if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the dashboard audit database.' }
    $panel = Join-Path $PSScriptRoot 'antigravity-panel'
    if (Test-Path -LiteralPath (Join-Path $panel 'plugin.json') -PathType Leaf) {
        $config = @{
            mcpServers = @{
                guard = @{
                    command = $python
                    args = @('-m', 'security_middleware.antigravity_panel',
                             '--model-dir', $model, '--audit-db', $auditDb,
                             '--panel-html', '${PLUGIN_ROOT}/protected-send.html')
                }
            }
        } | ConvertTo-Json -Depth 6
        [IO.File]::WriteAllText((Join-Path $panel 'mcp_config.json'), $config, [Text.UTF8Encoding]::new($false))
    }
    if (-not $configureHooks) {
        & $python (Join-Path $PSScriptRoot 'uninstall_detector.py') --register-bundle-only
        if ($LASTEXITCODE -ne 0) { throw 'Could not register the bundle for uninstall.' }
        Write-Host 'Installation complete.'
        if (-not $Acp) {
            $apps = @(Get-StartApps -ErrorAction SilentlyContinue)
            . (Join-Path $PSScriptRoot 'find_agy.ps1')
            $agy = Find-AntigravityCli
            $codex = Get-Command codex -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            $hasAntigravity = $agy -or ($apps | Where-Object Name -eq 'Antigravity')
            $hasCodex = $codex -or ($apps | Where-Object Name -eq 'Codex')
            $configuredAntigravity = $false
            if ($hasAntigravity) {
                & $python (Join-Path $PSScriptRoot 'uninstall_detector.py') --configure-user antigravity
                $configuredAntigravity = $LASTEXITCODE -eq 0
                if (-not $configuredAntigravity) { Write-Warning 'Antigravity user hooks could not be configured.' }
            } else {
                Write-Host 'Antigravity was not detected.'
            }
            if ($hasCodex) {
                & $python (Join-Path $PSScriptRoot 'uninstall_detector.py') --configure-user codex
                if ($LASTEXITCODE -eq 0) {
                    Write-Host 'Codex hooks registered. Review and trust them in Codex before use.'
                } else {
                    Write-Warning 'Codex user hooks could not be configured.'
                }
            } else {
                Write-Host 'Codex was not detected.'
            }
            if ($configuredAntigravity -and $agy -and (Test-Path -LiteralPath (Join-Path $panel 'mcp_config.json'))) {
                & $agy plugin validate $panel --strict
                if ($LASTEXITCODE -eq 0) {
                    & $agy plugin install $panel
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host 'Experimental Protected Send panel installed. Reopen Antigravity and open it beside a conversation.'
                    } else {
                        Write-Warning 'Antigravity panel installation did not succeed; the user hooks are registered.'
                    }
                } else {
                    Write-Warning 'Antigravity panel validation failed; the user hooks are registered.'
                }
            } elseif ($configuredAntigravity) {
                Write-Host 'Antigravity hook mode is registered. The Protected Send panel was not installed because the Antigravity CLI was not found.'
                Write-Host 'Optional CLI setup: https://antigravity.google/docs/getting-started?tab=cli'
            }
        }
        Write-Host 'Double-click Open Dashboard.cmd in this folder to view new decisions.'
        return
    }
    & $python (Join-Path $PSScriptRoot 'uninstall_detector.py') --register $Agent $Workspace
    if ($LASTEXITCODE -ne 0) { throw 'Could not register the workspace for uninstall.' }
    & $python -m security_middleware.agent_hooks install $Agent --workspace $Workspace --detector offline --model-dir $model --audit-db $auditDb
    if ($LASTEXITCODE -ne 0) { throw 'Could not configure the agent workspace.' }
    Write-Host "Configured $Agent for $Workspace. Reopen the workspace and enable the generated hooks in the agent."
    Write-Host 'Double-click Open Dashboard.cmd in this folder to view new decisions.'
} catch {
    Write-Host "Setup failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
