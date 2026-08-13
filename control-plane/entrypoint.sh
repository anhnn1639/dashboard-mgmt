#!/bin/sh
set -eu

install -d -m 0700 -o ops -g ops /run/secrets
install -d -m 0700 -o ops -g ops /var/lib/tram-ops
install -m 0400 -o ops -g ops /run/ca-src/agent-ca.key /run/secrets/agent-ca.key
install -m 0444 -o ops -g ops /run/ca-src/agent-ca.crt /run/secrets/agent-ca.crt
exec gosu ops "$@"
