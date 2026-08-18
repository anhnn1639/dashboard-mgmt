#!/bin/sh
set -eu

install -d -m 0700 -o ops -g ops /run/secrets
install -d -m 0700 -o ops -g ops /var/lib/tram-ops

recording_gid="${RECORDING_GID:-1000}"
case "$recording_gid" in
  ''|*[!0-9]*)
    echo "RECORDING_GID must be a positive numeric group id" >&2
    exit 1
    ;;
esac
if [ "$recording_gid" -le 0 ]; then
  echo "RECORDING_GID must be greater than zero" >&2
  exit 1
fi
recording_group="$(getent group "$recording_gid" | cut -d: -f1 || true)"
if [ -z "$recording_group" ]; then
  recording_group="tram-recordings"
  groupadd --gid "$recording_gid" "$recording_group"
fi
# gosu initializes the target user's supplementary groups. Register the
# Docker-provided recording GID in /etc/group first so the permission is not
# dropped when this entrypoint switches from root to ops.
usermod --append --groups "$recording_group" ops

for source_file in /run/ca-src/agent-ca.key /run/ca-src/agent-ca.crt; do
  if [ ! -f "$source_file" ]; then
    echo "Missing or invalid PKI file: $source_file" >&2
    echo "Run 'bash deploy/generate-pki.sh' on the Docker host, then recreate the containers." >&2
    exit 1
  fi
done

install -m 0400 -o ops -g ops /run/ca-src/agent-ca.key /run/secrets/agent-ca.key
install -m 0444 -o ops -g ops /run/ca-src/agent-ca.crt /run/secrets/agent-ca.crt
exec gosu ops "$@"
