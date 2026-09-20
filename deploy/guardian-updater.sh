#!/usr/bin/env bash
set -Eeuo pipefail

COMPOSE_DIR="${GUARDIAN_COMPOSE_DIR:-/root/guardian}"
RUNTIME_DIR="${GUARDIAN_RUNTIME_DIR:-${COMPOSE_DIR}/runtime}"
REQUEST_FILE="${RUNTIME_DIR}/update-request.json"
STATUS_FILE="${RUNTIME_DIR}/update-status.json"
DEFAULT_IMAGE="${GUARDIAN_IMAGE:-ghcr.io/dogwalkerg/guardian-backend:latest}"
LOCK_FILE="${RUNTIME_DIR}/update.lock"

mkdir -p "$RUNTIME_DIR"
exec 9>"$LOCK_FILE"
flock -n 9 || exit 0

write_status() {
  local status="$1" message="$2" version="${3:-}"
  local temp="${STATUS_FILE}.$$"
  jq -n --arg status "$status" --arg message "$message" --arg version "$version" --arg updatedAt "$(date -Is)" \
    '{status:$status,message:$message,version:$version,updatedAt:$updatedAt}' > "$temp"
  chmod 600 "$temp"
  mv -f "$temp" "$STATUS_FILE"
}

[[ -f "$REQUEST_FILE" ]] || exit 0
request="$(cat "$REQUEST_FILE")"
image="$(jq -r --arg fallback "$DEFAULT_IMAGE" '.image // $fallback' <<< "$request")"
version="$(jq -r '.version // "latest"' <<< "$request")"

# The updater must never execute a registry/image supplied outside the configured repository.
allowed_repo="${GUARDIAN_IMAGE_REPOSITORY:-ghcr.io/dogwalkerg/guardian-backend}"
if [[ "$image" != "$allowed_repo"\:* ]]; then
  write_status failed "image is outside the configured repository" "$version"
  rm -f "$REQUEST_FILE"
  exit 1
fi

write_status pulling "pulling $image" "$version"
override_file="${COMPOSE_DIR}/.guardian-update-compose.yml"
if ! printf 'services:\n  guardian-api:\n    image: %s\n  guardian-worker:\n    image: %s\n' "$image" "$image" > "$override_file"; then
  write_status failed "cannot write compose override" "$version"
  exit 1
fi

write_status restarting "restarting services" "$version"
if ! (cd "$COMPOSE_DIR" && docker compose --env-file .env -f docker-compose.yml -f .guardian-update-compose.yml pull guardian-api guardian-worker && docker compose --env-file .env -f docker-compose.yml -f .guardian-update-compose.yml up -d --no-build guardian-api guardian-worker); then
  write_status failed "docker compose update failed" "$version"
  rm -f "$REQUEST_FILE" "$override_file"
  exit 1
fi

write_status succeeded "services restarted successfully" "$version"
rm -f "$REQUEST_FILE" "$override_file"
