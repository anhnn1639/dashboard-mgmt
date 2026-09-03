#!/usr/bin/env bash
set -euo pipefail

profile=${1:?Linux profile is required}
output_dir=${2:?Output directory is required}
source_commit=${SOURCE_COMMIT:?SOURCE_COMMIT is required}
version=$(tr -d '\r\n' < agent/VERSION)
if ! printf '%s' "$source_commit" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "SOURCE_COMMIT must be a lowercase 40-character Git SHA" >&2
  exit 2
fi

case "$profile" in
  ubuntu-22.04) image=ubuntu:22.04; package_type=deb; native_packages="util-linux parted gdisk lvm2 e2fsprogs xfsprogs udev" ;;
  ubuntu-24.04) image=ubuntu:24.04; package_type=deb; native_packages="util-linux parted gdisk lvm2 e2fsprogs xfsprogs udev" ;;
  ol-7) image=oraclelinux:7-slim; package_type=rpm; native_packages="util-linux parted gdisk lvm2 e2fsprogs xfsprogs systemd" ;;
  ol-8) image=oraclelinux:8; package_type=rpm; native_packages="util-linux parted gdisk lvm2 e2fsprogs xfsprogs systemd-udev" ;;
  *) echo "Unsupported Linux profile: $profile" >&2; exit 2 ;;
esac

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tram-offline-deps.XXXXXX")
cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT HUP INT TERM
mkdir -p "$work_dir/packages" "$output_dir"

if [ "$package_type" = deb ]; then
  docker run --rm -v "$work_dir/packages:/out" "$image" bash -lc "
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get -y install --no-install-recommends dpkg-dev
    mkdir -p /tmp/archives/partial
    : > /tmp/empty-dpkg-status
    apt-get -y --download-only --reinstall --no-install-recommends \
      -o Dir::State::status=/tmp/empty-dpkg-status \
      -o Dir::Cache::archives=/tmp/archives install $native_packages
    cp /tmp/archives/*.deb /out/
    cd /out
    dpkg-scanpackages . /dev/null > Packages
  "
else
  case "$profile" in
    ol-7)
      docker run --rm -v "$work_dir/packages:/out" "$image" bash -lc "
        set -euo pipefail
        yum -y install yum-utils
        yumdownloader --resolve --destdir=/out $native_packages
        rpmkeys --checksig /out/*.rpm
      "
      ;;
    ol-8)
      docker run --rm -v "$work_dir/packages:/out" "$image" bash -lc "
        set -euo pipefail
        dnf -y install dnf-plugins-core
        dnf download --resolve --arch=x86_64,noarch --destdir /out $native_packages
        rpmkeys --checksig /out/*.rpm
      "
      ;;
  esac
fi

python3 - "$work_dir/packages" "$work_dir/manifest.json" "$profile" "$package_type" <<'PY'
import hashlib
import json
import pathlib
import sys

packages_dir, manifest_path, profile, package_type = sys.argv[1:]
paths = sorted(path for path in pathlib.Path(packages_dir).iterdir() if path.suffix == f".{package_type}")
if not paths:
    raise SystemExit("The offline dependency pack is empty")
entries = [
    {"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "sizeBytes": path.stat().st_size}
    for path in paths
]
payload = {"schema": 1, "profile": profile, "architecture": "x86_64", "packageType": package_type, "packages": entries}
pathlib.Path(manifest_path).write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY

archive="$output_dir/$profile-x86_64.tar"
tar --sort=name --mtime='@1704067200' --owner=0 --group=0 --numeric-owner -C "$work_dir" -cf "$archive" manifest.json packages
archive_size=$(stat -c %s "$archive")
if [ "$archive_size" -gt 99614720 ]; then
  echo "Offline dependency pack exceeds the 95 MiB repository limit: $archive" >&2
  exit 1
fi
python3 - "$archive" "$version" "$profile" "$source_commit" <<'PY'
import hashlib
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = {
    "schema": 1,
    "version": sys.argv[2],
    "artifactKind": "linux_offline_dependencies",
    "profile": sys.argv[3],
    "architecture": "x86_64",
    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    "sizeBytes": path.stat().st_size,
    "sourceCommit": sys.argv[4],
}
path.with_name(path.name + ".provenance.json").write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
sha256sum "$archive"
