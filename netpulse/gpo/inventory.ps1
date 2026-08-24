# ============================================================
#  NetPulse: отчёт инвентаря (софт + железо) с машины клиента.
#  Положить в GPO как Startup-скрипт (или назначение через schtasks).
#  Заполните три переменные ниже и всё.
# ============================================================

$NetPulseUrl   = "http://SERVER-NAME:8770"   # адрес сервера NetPulse
$NetPulseToken = ""                           # токен, если включён web_auth
$TimeoutSec    = 20

$ErrorActionPreference = "SilentlyContinue"

$headers = @{ "X-Auth" = $NetPulseToken }

# --- софт из реестра (64 и 32 бита) ---
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$software = Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  ForEach-Object {
    [pscustomobject]@{
      name      = $_.DisplayName
      version   = [string]$_.DisplayVersion
      publisher = [string]$_.Publisher
    }
  }

# --- железо ---
$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
$ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
       Select-Object -First 1).IPAddress

$body = [pscustomobject]@{
  hostname = $env:COMPUTERNAME
  user     = $env:USERNAME
  os       = $os
  ip       = $ip
  cpu      = $cpu
  ram_gb   = $ramGB
  software = @($software)
} | ConvertTo-Json -Depth 3 -Compress

try {
  Invoke-RestMethod -Method Post -Uri "$NetPulseUrl/api/invreport" `
    -ContentType "application/json; charset=utf-8" `
    -Headers $headers -Body $body -TimeoutSec $TimeoutSec
} catch {
  # молча: GPO-скрипт не должен сыпать ошибками на машинах юзеров
}
