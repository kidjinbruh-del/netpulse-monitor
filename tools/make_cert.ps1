# Генерация самоподписанного сертификата для HTTPS-режима NetPulse.
# Использует openssl из Git for Windows. Результат: netpulse/certs/*.pem
# После генерации включите в config.json: "web_tls": {"enabled": true}

$ErrorActionPreference = "Stop"

$openssl = @("C:\Program Files\Git\usr\bin\openssl.exe",
             "C:\Program Files\Git\mingw64\bin\openssl.exe",
             "openssl") | Where-Object {
    try { Get-Command $_ -ErrorAction SilentlyContinue } catch { $false }
} | Select-Object -First 1

if (-not $openssl) {
    Write-Error "openssl не найден (нужен Git for Windows)"
    exit 1
}

$certDir = Join-Path $PSScriptRoot "..\netpulse\certs"
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
$certDir = (Resolve-Path $certDir).Path

# IP подсети подставьте свой, если доступ с других машин
$lanIp = "192.168.1.50"

& $openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes `
    -keyout (Join-Path $certDir "key.pem") `
    -out (Join-Path $certDir "cert.pem") `
    -subj "/CN=netpulse" `
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:$lanIp"

Write-Host "Готово: $certDir\cert.pem и key.pem"
Write-Host "Теперь в config.json: `"web_tls`": {`"enabled`": true}"
Write-Host "Сертификат самоподписанный — браузер один раз попросит довериться."
