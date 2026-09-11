#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 compose.test.yaml|compose.external.yaml" >&2
  echo "Pass the same Compose overlay that the running deployment already uses." >&2
  exit 2
fi

override="$1"
case "$override" in
  compose.test.yaml|compose.external.yaml) ;;
  *) echo "Unsupported Compose overlay: $override" >&2; exit 2 ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
test -f "$override"
command -v timeout >/dev/null || { echo "Deployment verification requires the standard timeout command." >&2; exit 1; }

# Every verification step has an outer deadline as well as any in-process
# deadline. A stuck Docker CLI must not keep deployment waiting indefinitely.
verify_step() {
  label=$1
  limit=$2
  shift 2
  printf "[verify] %s (timeout %ss + 5s shutdown)\n" "$label" "$limit"
  if timeout --kill-after=5s "${limit}s" "$@"; then
    return 0
  else
    result=$?
    printf "Deployment verification failed: %s (exit %s). The containers have already been started; this is a verification failure.\n" "$label" "$result" >&2
    exit "$result"
  fi
}
compose_check() {
  description=$1
  shift
  verify_step "$description" 20 docker compose -f compose.yaml -f "$override" exec -T --interactive=false "$@" < /dev/null
}

git pull --ff-only origin main
revision=$(git rev-parse HEAD)

# Build all source-derived services from the checked-out revision. The dashboard
# carries the exact revision, while Guacamole carries the clipboard-sync extension.
docker compose -f compose.yaml -f "$override" build --pull --no-cache api
docker compose -f compose.yaml -f "$override" build --pull --no-cache --build-arg SOURCE_REVISION="$revision" dashboard
docker compose -f compose.yaml -f "$override" build --pull --no-cache guacamole web-console
docker compose -f compose.yaml -f "$override" up -d --force-recreate api dashboard guacamole web-console

# Probe the running process, not just source files inside the image. A missing
# route is HTTP 404; the correct protected route is HTTP 401 without credentials.
# Only these Python source probes need stdin; other exec calls explicitly close
# it because -T disables a TTY but does not disable Compose's interactive input.
verify_step "API protected routes" 75 docker compose -f compose.yaml -f "$override" exec -T --interactive=true api python - < deploy/verify-api-routes.py
sh deploy/verify-recording-storage.sh "$override"
compose_check "API SSH tools" api \
  sh -c 'command -v ssh-keyscan >/dev/null && command -v ssh >/dev/null && test -r /app/app/direct_sessions.py'

compose_check "Dashboard build revision" dashboard \
  node -e "const fs=require('fs'); const info=JSON.parse(fs.readFileSync('/app/public/build-info.json','utf8')); if(info.buildId !== process.argv[1]) { console.error('Dashboard build mismatch:', info.buildId, '!=', process.argv[1]); process.exit(1); } console.log('Dashboard build:', info.buildId);" "$revision"
compose_check "Dashboard update configuration" dashboard \
  grep -Fq 'Lưu cấu hình mẫu' /app/app/update-source-settings.tsx
compose_check "API update configuration" api \
  grep -Fq '/api/v1/settings/update-sources' /app/app/main.py
compose_check "API deletion approvals" api \
  grep -Fq '/api/v1/deletion-approvals' /app/app/main.py
compose_check "Dashboard managed connections" dashboard \
  grep -Fq '＋ Thêm kết nối' /app/app/managed-targets.tsx
compose_check "Guacamole clipboard extension" guacamole \
  test -r /etc/guacamole/extensions/tram-clipboard-sync.jar
compose_check "Guacamole clipboard extension version" guacamole \
  sh -c "jar --list --file /etc/guacamole/extensions/tram-clipboard-sync.jar | grep -Fq tram-clipboard-sync-v5.js"

verify_step "Guacamole JSON authentication and SSH/RDP protocols" 75 docker compose -f compose.yaml -f "$override" exec -T --interactive=true api gosu ops python - < deploy/verify-guacamole.py

verify_step "Container status" 20 docker compose -f compose.yaml -f "$override" ps api dashboard guacamole web-console
compose_check "Web console health" web-console \
  python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/health', timeout=5)"
echo "Deployment verified at commit $revision"
echo "Open a new tab or use the in-app reload prompt if an older tab is still open."
