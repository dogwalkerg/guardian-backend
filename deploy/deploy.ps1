param()
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if (-not (Test-Path .env)) { throw '缺少 .env，请先复制 .env.production.example 为 .env 并修改密码和 JWT_SECRET' }
New-Item -ItemType Directory -Force runtime | Out-Null
docker compose build guardian-api
docker compose up -d guardian-postgres guardian-redis
docker compose up -d guardian-api guardian-worker
Start-Sleep -Seconds 3
Invoke-RestMethod http://127.0.0.1:18080/health | ConvertTo-Json -Compress
docker compose ps
