# Safe compatibility launcher; elevated autostart is installed separately.
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSCommandPath
$PythonPath=Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $PythonPath)) {$PythonPath=(Get-Command python.exe).Source}
Set-Location -LiteralPath $Root
& $PythonPath (Join-Path $Root 'tools\launch_netpulse.py') --no-browser
exit $LASTEXITCODE
