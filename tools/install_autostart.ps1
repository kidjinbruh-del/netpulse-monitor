param([string]$PythonPath,[switch]$StartNow,[switch]$Remove,[switch]$Elevated)
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$TaskName='NetPulse'
$Identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$Principal=New-Object Security.Principal.WindowsPrincipal($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($Elevated) { throw 'Administrator privileges are required' }
    $Arguments='-NoProfile -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -Elevated'
    if ($PythonPath) { $Arguments+=' -PythonPath "'+$PythonPath+'"' }
    if ($StartNow) { $Arguments+=' -StartNow' }
    if ($Remove) { $Arguments+=' -Remove' }
    $Process=Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList $Arguments -PassThru -Wait
    exit $Process.ExitCode
}
if ($Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output 'NetPulse autostart removed'
    exit 0
}
if (-not $PythonPath) {
    $PythonPath=Join-Path $Root '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $PythonPath)) { $PythonPath=(Get-Command python.exe).Source }
}
$PythonPath=(Resolve-Path -LiteralPath $PythonPath).Path
& $PythonPath -c "import sys,psutil; assert sys.version_info >= (3,12)"
if ($LASTEXITCODE -ne 0) {throw 'Python 3.12+ and psutil are required'}
$Action=New-ScheduledTaskAction -Execute $PythonPath -Argument ('"'+(Join-Path $Root 'tools\admin_launcher.py')+'"') -WorkingDirectory $Root
$Trigger=New-ScheduledTaskTrigger -AtLogOn -User $Identity.Name
$TaskPrincipal=New-ScheduledTaskPrincipal -UserId $Identity.Name -LogonType Interactive -RunLevel Highest
$Settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
$Existing=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($Existing -and -not (($Existing.Actions | Out-String).Contains($Root))) {throw 'A NetPulse task from another checkout exists; inspect it before replacing'}
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $TaskPrincipal -Settings $Settings -Description 'NetPulse at user logon, administrator privileges, local dashboard' -Force | Out-Null
if ($StartNow) {Start-ScheduledTask -TaskName $TaskName}
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName,State,@{N='RunLevel';E={$_.Principal.RunLevel}}
