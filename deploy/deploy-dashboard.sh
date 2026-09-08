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

git pull --ff-only origin main
revision=$(git rev-parse HEAD)

# Build all source-derived services from the checked-out revision. The dashboard
# carries the exact revision, while Guacamole carries the clipboard-sync extension.
docker compose -f compose.yaml -f "$override" build --pull --no-cache api
docker compose -f compose.yaml -f "$override" build --pull --no-cache --build-arg SOURCE_REVISION="$revision" dashboard
docker compose -f compose.yaml -f "$override" build --pull --no-cache guacamole
docker compose -f compose.yaml -f "$override" up -d --force-recreate api dashboard guacamole

# Probe the running process, not just source files inside the image. A missing
# route is HTTP 404; the correct protected route is HTTP 401 without credentials.
docker compose -f compose.yaml -f "$override" exec -T api python - < deploy/verify-api-routes.py
docker compose -f compose.yaml -f "$override" exec -T api \
  sh -c 'command -v ssh-keyscan >/dev/null && command -v ssh >/dev/null && test -r /app/app/direct_sessions.py'

docker compose -f compose.yaml -f "$override" exec -T dashboard \
  node -e "const fs=require('fs'); const info=JSON.parse(fs.readFileSync('/app/public/build-info.json','utf8')); if(info.buildId !== process.argv[1]) { console.error('Dashboard build mismatch:', info.buildId, '!=', process.argv[1]); process.exit(1); } console.log('Dashboard build:', info.buildId);" "$revision"
docker compose -f compose.yaml -f "$override" exec -T dashboard \
  grep -Fq 'Lưu cấu hình mẫu' /app/app/update-source-settings.tsx
docker compose -f compose.yaml -f "$override" exec -T api \
  grep -Fq '/api/v1/settings/update-sources' /app/app/main.py
docker compose -f compose.yaml -f "$override" exec -T api \
  grep -Fq '/api/v1/deletion-approvals' /app/app/main.py
docker compose -f compose.yaml -f "$override" exec -T dashboard \
  grep -Fq '＋ Thêm kết nối' /app/app/managed-targets.tsx
docker compose -f compose.yaml -f "$override" exec -T guacamole \
  test -r /etc/guacamole/extensions/tram-clipboard-sync.jar
docker compose -f compose.yaml -f "$override" exec -T guacamole \
  sh -c "jar --list --file /etc/guacamole/extensions/tram-clipboard-sync.jar | grep -Fq tram-clipboard-sync-v3.js"

docker compose -f compose.yaml -f "$override" ps api dashboard guacamole
echo "Deployment verified at commit $revision"
echo "Open a new tab or use the in-app reload prompt if an older tab is still open."
