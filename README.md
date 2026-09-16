# Guardian Backend

云端后台服务，使用 TypeScript、Fastify、PostgreSQL、Redis 和 WebSocket，配套 Docker Compose 部署。

## GitHub Container Registry

默认镜像：

```text
ghcr.io/dogwalkerg/guardian-backend:latest
```

GitHub Actions 工作流位于 `.github/workflows/docker-publish.yml`，推送到 `main` 或 `v*.*.*` 标签后自动构建并发布 `linux/amd64` 镜像。

## VPS 部署

```bash
mkdir -p /opt/guardian-backend
cd /opt/guardian-backend
# 上传 docker-compose.yml、db/001_init.sql 和 .env.production.example
cp .env.production.example .env
nano .env

# 私有 GHCR 镜像需要先登录；使用具有 read:packages 权限的 GitHub Token
printf '%s' "$GHCR_READ_TOKEN" | docker login ghcr.io -u wgu76989-arch --password-stdin

docker compose pull
docker compose up -d
docker compose ps
curl http://127.0.0.1:18080/health
```

API 通过宝塔反向代理到 `http://127.0.0.1:18080`，WebSocket 路径为 `/ws`。

