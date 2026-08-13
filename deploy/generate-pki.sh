#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pki_dir="$script_dir/pki"
umask 077
mkdir -p "$pki_dir"

if [[ -e "$pki_dir/agent-ca.key" ]]; then
  echo "PKI already exists at $pki_dir; refusing to overwrite." >&2
  exit 1
fi

openssl ecparam -name prime256v1 -genkey -noout -out "$pki_dir/agent-ca.key"
openssl req -x509 -new -sha256 -key "$pki_dir/agent-ca.key" -days 3650 \
  -subj "/O=Tram Van Hanh/OU=Agent PKI/CN=Tram Van Hanh Agent Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$pki_dir/agent-ca.crt"
chmod 600 "$pki_dir/agent-ca.key"
chmod 644 "$pki_dir/agent-ca.crt"
echo "Created agent CA in $pki_dir. Back up the key offline and restrict root access."
