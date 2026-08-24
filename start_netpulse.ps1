# NetPulse launcher: убивает прошлый экземпляр на 8770 и стартует сервер.
# Используется задачей планировщика "NetPulse" (RunLevel Highest).
$conn = Get-NetTCPConnection -LocalPort 8770 -State Listen -ErrorAction SilentlyContinue
foreach ($c in $conn) {
    try { Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue } catch {}
}
Start-Sleep -Seconds 1
Set-Location -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)
python -m netpulse
