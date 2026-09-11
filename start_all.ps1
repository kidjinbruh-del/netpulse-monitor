# NetPulse: единый запуск всей решётки с правами администратора.
#
# Запускает:
#   1) node0  (mesh\node0,  P2P-узел, порт 9000)
#   2) node1  (mesh\node1,  P2P-узел, порт 9001)
#   3) hub    (веб-панель + мульти-таргет мост в решётку, порт 8771)
#
# При запуске без прав — сам перезапускается через UAC (RunLevel Highest).

param(
    [switch]$NoUAC,
    [switch]$Open
)

$ErrorActionPreference = "Stop"

# ---- определение корня и python ----
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Py = "C:\Users\ebann\AppData\Local\Python\pythoncore-3.14-64\python.exe"

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

# ---- 1. гасим старые процессы ----
Write-Host ""
Write-Host "[netpulse] Остановка старых процессов..." -ForegroundColor Cyan
Stop-PortOwner 9000 "node0"
Stop-PortOwner 9001 "node1"
Stop-PortOwner 8771 "hub"
Start-Sleep -Seconds 2

# ---- 2. ноды решётки ----
Write-Host ""
Write-Host "[netpulse] Запуск P2P-узлов..." -ForegroundColor Cyan
$p0 = Start-Node (Join-Path $Root "mesh\node0") "node0"
$p1 = Start-Node (Join-Path $Root "mesh\node1") "node1"

# дождимся слушающих портов
Write-Host "[netpulse] ждём готовности узлов (9000/9001)..." -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds(40)
while ((Get-Date) -lt $deadline) {
    $l0 = Get-NetTCPConnection -LocalPort 9000 -State Listen -ErrorAction SilentlyContinue
    $l1 = Get-NetTCPConnection -LocalPort 9001 -State Listen -ErrorAction SilentlyContinue
    if ($l0 -and $l1) { break }
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
    Write-Host "[netpulse]   node0: ws://127.0.0.1:9000  node1: ws://127.0.0.1:9001" -ForegroundColor Green
    if ($Open) {
        Start-Process "http://127.0.0.1:8771"
    }
} else {
    Write-Host "[netpulse] hub не поднялся за отведённое время — см. logs\hub.err.log" -ForegroundColor Red
}
Write-Host ""