param([string]$PythonPath)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $PythonPath) {
    $LocalPython = Join-Path $Root '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $LocalPython) { $PythonPath = $LocalPython }
    else { $PythonPath = (Get-Command python.exe -ErrorAction Stop).Source }
}
if (-not (Test-Path -LiteralPath $PythonPath)) { throw 'Python executable not found' }
& $PythonPath -c "import sys; assert sys.version_info >= (3,12), 'Python 3.12+ required'"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.12+ required' }
$Windowless = Join-Path (Split-Path -Parent $PythonPath) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $Windowless)) { $Windowless = $PythonPath }
$Desktop = [Environment]::GetFolderPath('Desktop')
$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut((Join-Path $Desktop 'NetPulse.lnk'))
$Shortcut.TargetPath = $Windowless
$Shortcut.Arguments = '"' + (Join-Path $Root 'tools\launch_netpulse.py') + '"'
$Shortcut.WorkingDirectory = $Root
$Shortcut.Description = 'Start NetPulse and open the local operations dashboard'
$Shortcut.WindowStyle = 7
$Shortcut.IconLocation = "$env:SystemRoot\System32\shell32.dll,14"
$Shortcut.Save()
Write-Output (Join-Path $Desktop 'NetPulse.lnk')
