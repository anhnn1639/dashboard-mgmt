#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Pass the active Compose overlay to the recording storage check." >&2
  exit 2
fi
override="$1"
case "$override" in
  compose.test.yaml|compose.external.yaml) ;;
  *) echo "Unsupported Compose overlay." >&2; exit 2 ;;
esac
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
command -v timeout >/dev/null || { echo "The recording storage check requires the standard timeout command." >&2; exit 1; }
compose_exec() {
  timeout 20 docker compose -f compose.yaml -f "$override" exec -T "$@"
}

# Docker exec uses the guacd image's configured identity (UID 1000). The check
# must fail instead of accidentally proving only that root can write the mount.
if ! marker_path=$(compose_exec guacd sh -c '
  set -eu
  test "$(id -u)" = 1000
  marker=$(mktemp /recordings/.operation-portal-storage.XXXXXXXXXXXX)
  if ! chmod 0640 "$marker" || ! printf "operation-portal-recording-readiness\n" > "$marker"; then
    rm -f -- "$marker"
    exit 1
  fi
  printf "%s\n" "$marker"
'); then
  echo "Recording storage check failed: guacd cannot create a recording with its service identity. Check RECORDING_DIR ownership and the recording-init result." >&2
  exit 1
fi

# Only the exact unpredictable marker generated above may be cleaned up. Never
# expand globs, enumerate recording files for deletion, or change their modes.
case "$marker_path" in
  /recordings/.operation-portal-storage.*) ;;
  *) echo "Invalid recording readiness marker response." >&2; exit 1 ;;
esac
marker_suffix=${marker_path#/recordings/.operation-portal-storage.}
case "$marker_suffix" in
  ''|*[!A-Za-z0-9]*) echo "Invalid recording readiness marker response." >&2; exit 1 ;;
esac
test "${#marker_suffix}" = 12 || exit 1
cleanup() {
  compose_exec guacd rm -f -- "$marker_path"
}
trap 'cleanup || true' 0
trap 'exit 1' HUP INT TERM

# Match entrypoint.sh: gosu initializes the supplementary recording group from
# /etc/group. A default docker exec as root would mask the production failure.
compose_exec api gosu ops python - \
  ".operation-portal-storage.$marker_suffix" < deploy/verify-recording-storage.py
cleanup
trap - 0
