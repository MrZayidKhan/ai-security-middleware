param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$wpf = Join-Path $framework 'WPF'
$output = New-Item -ItemType Directory -Path $OutputDirectory -Force
$references = @('WindowsBase', 'PresentationCore', 'PresentationFramework', 'UIAutomationClient', 'UIAutomationTypes') |
    ForEach-Object { '/reference:' + (Join-Path $wpf "$_.dll") }
$references += @('System.Windows.Forms', 'System.Drawing', 'System.Web.Extensions', 'System.Xaml') |
    ForEach-Object { '/reference:' + (Join-Path $framework "$_.dll") }
$sources = @('Program.cs', 'DetectorClient.cs', 'AntigravityTransport.cs', 'NativeSendMonitor.cs') |
    ForEach-Object { Join-Path $PSScriptRoot $_ }
$flags = @('/nologo', '/target:winexe', '/platform:x64', '/optimize+', '/langversion:5',
           ("/win32manifest:" + (Join-Path $PSScriptRoot 'app.manifest')),
           ("/out:" + (Join-Path $output.FullName 'ProtectedSend.exe')))
& (Join-Path $framework 'csc.exe') @flags @references @sources
exit $LASTEXITCODE
