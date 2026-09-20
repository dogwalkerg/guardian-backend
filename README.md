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

## 管理员控制台和一键更新

管理员控制台地址为 `/admin/`，使用 `ADMIN_USERNAME` 与 `ADMIN_PASSWORD_HASH` 登录。生产环境不要使用明文 `ADMIN_PASSWORD`，可使用 `node -e "console.log(require('bcryptjs').hashSync('your-password', 10))"` 生成 bcrypt 哈希。

控制台只会写入 `runtime/update-request.json`，不会直接暴露 Docker Socket。将 `deploy/guardian-updater.sh` 复制到 VPS 的部署目录，并安装 `guardian-updater.service` 与 `guardian-updater.timer`，updater 才会按请求拉取已白名单镜像并重启 `guardian-api`、`guardian-worker`：

```bash
cd /root/guardian
mkdir -p runtime
chown -R 1000:1000 runtime
chmod 700 deploy/guardian-updater.sh
cp deploy/guardian-updater.service /etc/systemd/system/
cp deploy/guardian-updater.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now guardian-updater.timer
systemctl status guardian-updater.timer
```

更新过程：GitHub Actions 发布镜像 -> 管理员点击更新 -> API 写入请求 -> systemd updater 使用临时 Compose override 执行 `docker compose pull` 和 `up -d --no-build` -> 状态写回控制台。updater 只允许 `ghcr.io/dogwalkerg/guardian-backend:*`，不执行任意管理员输入的 shell 命令。

要让版本检查显示明确的最新版本，请按 `v1.0.1` 这样的格式推送 Git tag；工作流会同时发布镜像并创建 GitHub Release。仅推送 `main` 也会更新 `latest` 镜像，但不会自动生成带发布说明的版本号。

