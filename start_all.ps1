# NetPulse: единый запуск с правами администратора.
#
# Запускает:
#   1) node0  (mesh\node0,  настоящая P2P-нода, порт 9000)
#   2) hub    (веб-панель + мост в решётку, порт 8771)
#
# По пути гасит зависшие/симулятивные процессы (9001, 8770).
# При запуске без прав — сам перезапускается через UAC (RunLevel Highest).

param(
    [switch]$NoUAC,
    [switch]$Open
)

$ErrorActionPreference = "Stop"

# ---- определение корня и python ----
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
# NOTE: не инлайнить (Get-Command ...).Source внутрь @(...) через запятую —
# парсер Windows PowerShell 5.1 ломается на таком переносе строки.
$PyShim = $null
$Py3Shim = $null
try { $PyShim = (Get-Command python -ErrorAction SilentlyContinue).Source } catch {}
try { $Py3Shim = (Get-Command python3 -ErrorAction SilentlyContinue).Source } catch {}
$PyCandidates = @($env:NETPULSE_PYTHON, $PyShim, $Py3Shim)
$LocalAppData = [Environment]::GetFolderPath('LocalApplicationData')
foreach ($ver in @('3.14', '3.13', '3.12', '3.11', '3.10')) {
    $PyCandidates += Join-Path $LocalAppData "Python\pythoncore-$ver-64\python.exe"
}
$Py = $PyCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
if (-not $Py) {
    throw "[netpulse] Python не найден. Установите Python или задайте переменную окружения NETPULSE_PYTHON."
}

# ---- самоподъём прав ----
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $NoUAC) {
    Write-Host "[netpulse] Нет прав администратора - перезапуск через UAC..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList (
        "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -NoUAC")
    exit 0
}
if (-not $isAdmin) {
    Write-Host "[netpulse] ВАЖНО: запуск без прав администратора (UAC отменён)." -ForegroundColor Red
}

function Stop-PortOwner([int]$Port, [string]$Name) {
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conn) {
        try {
            Write-Host "[netpulse] останавливаю $Name (PID $($c.OwningProcess), порт $Port)"
            Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
        } catch {}
    }
}

function Start-Node([string]$NodeDir, [string]$LogTag) {
    $out = Join-Path $Root "logs\$LogTag.out.log"
    $err = Join-Path $Root "logs\$LogTag.err.log"
    New-Item -ItemType Directory -Force -Path (Split-Path $out -Parent) | Out-Null
    Set-Location -LiteralPath $Root
    $p = Start-Process $Py -ArgumentList (
        "-m", "netpulse.p2p_core.node_runner", "--workdir", "`"$NodeDir`"") `
        -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err `
        -PassThru
    Write-Host "[netpulse] $LogTag запущен (PID $($p.Id), workdir $NodeDir)"
    Start-Sleep -Seconds 1
    return $p
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "NETPULSE — единый запуск решётки (администратор)"    -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# ---- 1. гасим старые процессы (включая симулятивные/зависшие ноды) ----
Write-Host ""
Write-Host "[netpulse] Остановка старых процессов..." -ForegroundColor Cyan
Stop-PortOwner 9000 "node0"
Stop-PortOwner 9001 "ex-node1"
Stop-PortOwner 8770 "stale-hub"
Stop-PortOwner 8771 "hub"
Start-Sleep -Seconds 2

# ---- 2. нода решётки (одна настоящая, mesh\node0, порт 9000) ----
Write-Host ""
Write-Host "[netpulse] Запуск P2P-ноды..." -ForegroundColor Cyan
$p0 = Start-Node (Join-Path $Root "mesh\node0") "node0"

# дождёмся слушающего порта
Write-Host "[netpulse] ждём готовности ноды (9000)..." -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds(40)
while ((Get-Date) -lt $deadline) {
    $l0 = Get-NetTCPConnection -LocalPort 9000 -State Listen -ErrorAction SilentlyContinue
    if ($l0) { break }
    Start-Sleep -Seconds 1
    Write-Host "." -NoNewline -ForegroundColor DarkGray
}
Write-Host ""

# ---- 3. hub (веб + мост) ----
Write-Host ""
Write-Host "[netpulse] Запуск hub (веб + мост)..." -ForegroundColor Cyan
Set-Location -LiteralPath $Root
$hOut = Join-Path $Root "logs\hub.out.log"
$hErr = Join-Path $Root "logs\hub.err.log"
$hub = Start-Process $Py -ArgumentList "-m", "netpulse" `
    -WindowStyle Hidden -RedirectStandardOutput $hOut -RedirectStandardError $hErr `
    -PassThru
Write-Host "[netpulse] hub запущен (PID $($hub.Id), веб-порт 8771)"

# ---- 4. статус ----
Write-Host ""
Write-Host "[netpulse] ждём веб-интерфейс..." -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds(30)
$webOk = $false
while ((Get-Date) -lt $deadline) {
    if (Get-NetTCPConnection -LocalPort 8771 -State Listen -ErrorAction SilentlyContinue) {
        $webOk = $true; break
    }
    Start-Sleep -Seconds 1
}
if ($webOk) {
    Write-Host ""
    Write-Host "[netpulse] ГОТОВО:" -ForegroundColor Green
    Write-Host "[netpulse]   веб-панель: http://127.0.0.1:8771" -ForegroundColor Green
    Write-Host "[netpulse]   node0: ws://127.0.0.1:9000 (настоящая нода)" -ForegroundColor Green
    try {
        $who = Invoke-RestMethod -Uri "http://127.0.0.1:8771/api/whoami" -TimeoutSec 10
        Write-Host "[netpulse]   API: OK (whoami -> $($who.user)/$($who.role))" -ForegroundColor Green
    } catch {
        Write-Host "[netpulse]   API: порт слушает, но /api/whoami не ответил — см. logs\hub.err.log" -ForegroundColor Yellow
    }
    if ($Open) {
        Start-Process "http://127.0.0.1:8771"
    }
} else {
    Write-Host "[netpulse] hub не поднялся за отведённое время — см. logs\hub.err.log" -ForegroundColor Red
}
Write-Host ""