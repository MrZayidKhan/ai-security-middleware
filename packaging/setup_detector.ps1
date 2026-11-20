param(
    [ValidateSet('codex', 'antigravity')]
    [string]$Agent,
    [string]$Workspace
)

$ErrorActionPreference = 'Stop'

try {
    if (-not $Agent) {
        Write-Host '1. Codex'
        Write-Host '2. Antigravity'
        switch (Read-Host 'Choose your agent (1 or 2)') {
            '1' { $Agent = 'codex' }
            '2' { $Agent = 'antigravity' }
            default { throw 'Choose 1 for Codex or 2 for Antigravity.' }
        }
    }
    if (-not $Workspace) {
        $Workspace = (Read-Host 'Enter the full path to the workspace to protect').Trim().Trim('"')
    }
    if (-not $Workspace -or -not (Test-Path -LiteralPath $Workspace -PathType Container)) {
        throw 'The selected workspace must be an existing folder.'
    }
    $Workspace = (Resolve-Path -LiteralPath $Workspace).Path
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
    if (-not (Get-Command py.exe -ErrorAction SilentlyContinue)) {
        throw 'This setup needs matching Windows Python with the Python launcher.'
    }
    $runtime = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'python-version.txt') -Raw).Trim()
    if ($runtime -notmatch '^3\.(13|14)$') { throw 'Invalid bundled Python version.' }
    & py.exe "-$runtime" -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "Could not create the Python $runtime environment." }
    $python = Join-Path $venv 'Scripts\python.exe'
    & $python -m pip --isolated install --disable-pip-version-check --no-index --find-links $wheels 'ai-security-middleware[gateway]' onnxruntime tokenizers numpy
    if ($LASTEXITCODE -ne 0) { throw 'Offline dependency installation failed. Check Python and CPU compatibility.' }
    & $python -c "import sys; from pathlib import Path; from security_middleware.horizon_detector import HorizonDetector; result = HorizonDetector.from_advisory_profile(Path(sys.argv[1])).detect('Summarize these notes.'); sys.exit(result.risk == 'unavailable')" $model
    if ($LASTEXITCODE -ne 0) { throw 'The offline detector failed its startup check.' }
    $auditDb = Join-Path $PSScriptRoot 'runtime_data\security_events.db'
    & $python -c "import sys; from pathlib import Path; from security_middleware.audit_log import initialize_audit_database; path = Path(sys.argv[1]); path.parent.mkdir(exist_ok=True); initialize_audit_database(path)" $auditDb
    if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the dashboard audit database.' }
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
