#!/bin/sh
set -eu

install -d -m 0700 -o ops -g ops /run/secrets
install -d -m 0700 -o ops -g ops /var/lib/tram-ops

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
