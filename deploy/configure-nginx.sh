#!/bin/sh
set -eu

umask 077

usage() {
  echo "Usage: sudo sh deploy/configure-nginx.sh DOMAIN PUBLIC_CERT PUBLIC_KEY [NGINX_OUTPUT]" >&2
  echo "Example: sudo sh deploy/configure-nginx.sh ops.sbsi.vn /home/system/sbsi.vn.pem /home/system/sbsi.vn.key" >&2
  exit 2
}

[ "$#" -ge 3 ] && [ "$#" -le 4 ] || usage

domain=$1
public_certificate=$2
public_key=$3
nginx_output=${4:-/etc/nginx/sites-available/$domain}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
env_file=$repository_root/.env
template=$script_dir/nginx-dashboard.conf.example
caddy_ca=$repository_root/deploy/pki/public/server-ca.crt

printf '%s' "$domain" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$' || {
  echo "Invalid DNS domain: $domain" >&2
  exit 2
}

for path in "$public_certificate" "$public_key" "$nginx_output" "$repository_root"; do
  printf '%s' "$path" | grep -Eq '^/[A-Za-z0-9._/ -]+$' || {
    echo "Unsafe path: $path" >&2
    exit 2
  }
done

[ -f "$env_file" ] || {
  echo "Missing $env_file. Copy .env.example and configure secrets first." >&2
  exit 1
}
[ -r "$public_certificate" ] || { echo "Cannot read public certificate: $public_certificate" >&2; exit 1; }
[ -r "$public_key" ] || { echo "Cannot read public key: $public_key" >&2; exit 1; }
[ -r "$template" ] || { echo "Cannot read Nginx template: $template" >&2; exit 1; }

openssl x509 -in "$public_certificate" -noout -checkhost "$domain" >/dev/null
openssl pkey -in "$public_key" -passin pass: -noout -check >/dev/null

nginx_directory=$(dirname -- "$nginx_output")
[ -d "$nginx_directory" ] || {
  echo "Nginx output directory does not exist: $nginx_directory" >&2
  exit 1
}

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
env_backup=$env_file.before-nginx-$timestamp
cp -p "$env_file" "$env_backup"
chmod 0600 "$env_backup"

upsert_env() {
  key=$1
  value=$2
  temporary=$(mktemp "$env_file.tmp.XXXXXX")
  awk -v key="$key" -v value="$value" '
    BEGIN { found = 0 }
    index($0, key "=") == 1 {
      if (!found) print key "=" value
      found = 1
      next
    }
    { print }
    END { if (!found) print key "=" value }
  ' "$env_file" > "$temporary"
  chmod 0600 "$temporary"
  chown --reference="$env_file" "$temporary"
  mv "$temporary" "$env_file"
}

upsert_env OPS_DOMAIN "$domain"
upsert_env WEB_BIND_PORT 3000
upsert_env WEB_TLS_TRUST system

rendered=$(mktemp "${TMPDIR:-/tmp}/tram-nginx.XXXXXX")
cleanup() { rm -f "$rendered"; }
trap cleanup EXIT HUP INT TERM

awk \
  -v domain="$domain" \
  -v certificate="$public_certificate" \
  -v key="$public_key" \
  -v caddy_ca="$caddy_ca" '
  {
    gsub(/__OPS_DOMAIN__/, domain)
    gsub(/__PUBLIC_CERTIFICATE__/, certificate)
    gsub(/__PUBLIC_CERTIFICATE_KEY__/, key)
    gsub(/__CADDY_CA_CERTIFICATE__/, caddy_ca)
    print
  }
' "$template" > "$rendered"

if [ -e "$nginx_output" ]; then
  nginx_backup=$nginx_output.before-tram-$timestamp
  cp -p "$nginx_output" "$nginx_backup"
  echo "Backed up existing Nginx config to $nginx_backup"
fi
install -m 0644 "$rendered" "$nginx_output"

echo "Updated $env_file (backup: $env_backup)"
echo "Rendered Nginx config: $nginx_output"
echo "Next: rebuild Docker, verify $caddy_ca exists, then run nginx -t and reload Nginx."
