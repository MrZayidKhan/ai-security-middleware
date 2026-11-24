function Find-AntigravityCli {
    param([string]$LocalAppData = [Environment]::GetFolderPath('LocalApplicationData'))

    if ($LocalAppData) {
        $installed = Join-Path $LocalAppData 'agy\bin\agy.exe'
        if (Test-Path -LiteralPath $installed -PathType Leaf) {
            return (Get-Item -LiteralPath $installed).FullName
        }
    }
    $command = Get-Command agy.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($command) { return $command.Source }
}
