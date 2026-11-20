$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$ollamaJob = $null
$exitCode = 1

try {
    $versionUrl = 'http://127.0.0.1:11434/api/version'
    try {
        Invoke-RestMethod $versionUrl -TimeoutSec 2 | Out-Null
    } catch {
        $ollamaJob = Start-Job -ScriptBlock {
            $env:OLLAMA_HOST = '127.0.0.1:11434'
            ollama serve
        }
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            try {
                Invoke-RestMethod $versionUrl -TimeoutSec 1 | Out-Null
                break
            } catch {
                Start-Sleep -Milliseconds 500
            }
        }
    }
    & .\.venv\Scripts\python.exe -m scripts.evaluate_full_corpora verifier
    $exitCode = $LASTEXITCODE
} finally {
    if ($null -ne $ollamaJob) {
        Stop-Job $ollamaJob
        Remove-Job $ollamaJob
    }
}
exit $exitCode
