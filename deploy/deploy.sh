#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  echo "缺少 .env，请先复制 .env.production.example 为 .env 并修改密码和 JWT_SECRET"
  exit 1
fi

docker compose build guardian-api
docker compose up -d guardian-postgres guardian-redis
docker compose up -d guardian-api guardian-worker
sleep 3
curl --fail --silent --show-error http://127.0.0.1:18080/health
echo
docker compose ps
