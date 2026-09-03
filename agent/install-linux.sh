#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo ./TramAgent-Linux.run" >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bootstrap_source=${1:-}

if [ ! -r /etc/os-release ]; then
  echo "Unsupported Linux: /etc/os-release is missing" >&2
  exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release
os_id=$(printf '%s' "${ID:-}" | tr '[:upper:]' '[:lower:]')
os_version=${VERSION_ID:-}
case "$os_id:$os_version" in
  ubuntu:22.04) linux_profile="ubuntu-22.04" ;;
  ubuntu:24.04) linux_profile="ubuntu-24.04" ;;
  ol:7*) linux_profile="ol-7" ;;
  ol:8*) linux_profile="ol-8" ;;
  *)
    echo "Unsupported Linux release: ${PRETTY_NAME:-$os_id $os_version}" >&2
    echo "Supported: Ubuntu 22.04/24.04 and Oracle Linux 7/8 (x86_64)." >&2
    exit 1
    ;;
esac

architecture=$(uname -m)
case "$architecture" in
  x86_64|amd64) artifact="$script_dir/linux/x86_64/tram-agent" ;;
  *)
    echo "Unsupported architecture: $architecture. This package contains the x86_64 Agent." >&2
    exit 1
    ;;
esac

for required_command in install systemctl; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "Missing required operating-system command: $required_command" >&2
    exit 1
  fi
done

if [ ! -s "$artifact" ]; then
  echo "Standalone Agent artifact is missing from the installer" >&2
  exit 1
fi

identity_state="new"
identity_files="/etc/tram-agent/agent.json /etc/tram-agent/agent.crt /etc/tram-agent/agent.key /etc/tram-agent/agent-ca.crt /etc/tram-agent/server-ca.crt"
identity_file_count=0
for identity_file in $identity_files; do
  if [ -s "$identity_file" ]; then
    identity_file_count=$((identity_file_count + 1))
  fi
done
if [ "$identity_file_count" -eq 5 ]; then
  identity_state="enrolled"
elif [ "$identity_file_count" -ne 0 ]; then
  echo "Existing Agent identity is incomplete; installation stopped before changing the service." >&2
  echo "Do not delete /etc/tram-agent automatically. Restore its certificate/key backup or retire the old server in the dashboard before a deliberate clean enrollment." >&2
  exit 1
fi

# Native Disk/LVM tools are carried inside this one-time installer. The pack is
# built from the signed repositories for exactly one supported release, hashed
# by the build workflow and verified again before any package manager runs.
# Repository configuration is disabled for the local install, so an air-gapped
# endpoint never falls back to the Internet or an internal mirror.
storage_commands="lsblk blkid mount umount findmnt blockdev partx wipefs udevadm parted partprobe sgdisk pvs vgs lvs pvcreate pvresize vgcreate vgextend lvcreate lvextend lvremove mkfs.ext4 resize2fs mkfs.xfs xfs_growfs"
missing_storage=""
for storage_command in $storage_commands; do
  if ! command -v "$storage_command" >/dev/null 2>&1; then
    missing_storage="$missing_storage $storage_command"
  fi
done
if [ -n "$missing_storage" ]; then
  for required_command in sha256sum tar; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
      echo "Missing required offline installer command: $required_command" >&2
      exit 1
    fi
  done
  if [ ! -s "$script_dir/linux-profile" ] || [ "$(tr -d '\r\n' < "$script_dir/linux-profile")" != "$linux_profile" ]; then
    echo "This offline package does not match ${PRETTY_NAME:-$os_id $os_version}. Download the $linux_profile package from the dashboard." >&2
    exit 1
  fi
  if [ ! -s "$script_dir/offline-dependencies.tar" ] || [ ! -s "$script_dir/offline-dependencies.sha256" ]; then
    echo "The $linux_profile offline dependency pack is missing." >&2
    exit 1
  fi
  echo "Installing bundled offline OS storage dependencies (missing:$missing_storage)"
  (cd "$script_dir" && sha256sum -c offline-dependencies.sha256)
  package_root="$script_dir/offline-dependencies"
  mkdir -m 0700 "$package_root"
  tar -xf "$script_dir/offline-dependencies.tar" --no-same-owner -C "$package_root"
  case "$os_id" in
    ubuntu)
      if ! command -v apt-get >/dev/null 2>&1; then
        echo "apt-get is required to install the bundled Ubuntu packages" >&2
        exit 1
      fi
      if [ ! -s "$package_root/packages/Packages" ]; then
        echo "The Ubuntu offline package index is missing" >&2
        exit 1
      fi
      mkdir -m 0700 "$package_root/empty-sources" "$package_root/apt-lists"
      mkdir -m 0700 "$package_root/apt-lists/partial" "$package_root/packages/partial"
      printf 'deb [trusted=yes] file:%s ./\n' "$package_root/packages" > "$package_root/offline.list"
      echo "Refreshing the bundled local package index"
      apt-get \
        -o APT::Sandbox::User=root \
        -o Dir::Etc::sourcelist="$package_root/offline.list" \
        -o Dir::Etc::sourceparts="$package_root/empty-sources" \
        -o Dir::State::lists="$package_root/apt-lists" \
        -o Dir::Cache::archives="$package_root/packages" \
        -o Acquire::Languages=none update
      DEBIAN_FRONTEND=noninteractive apt-get -y --no-download --no-install-recommends \
        -o APT::Sandbox::User=root \
        -o Dir::Etc::sourcelist="$package_root/offline.list" \
        -o Dir::Etc::sourceparts="$package_root/empty-sources" \
        -o Dir::State::lists="$package_root/apt-lists" \
        -o Dir::Cache::archives="$package_root/packages" \
        -o Acquire::Languages=none install util-linux parted gdisk lvm2 e2fsprogs xfsprogs udev
      ;;
    ol)
      set -- "$package_root"/packages/*.rpm
      [ -f "$1" ] || { echo "The RPM offline dependency pack is empty" >&2; exit 1; }
      if command -v rpmkeys >/dev/null 2>&1; then
        rpmkeys --checksig "$@"
      fi
      if command -v dnf >/dev/null 2>&1; then
        dnf -y --disablerepo='*' install "$@"
      elif command -v yum >/dev/null 2>&1; then
        yum -y --disablerepo='*' localinstall "$@"
      else
        echo "dnf/yum is required to install the bundled Oracle Linux packages" >&2
        exit 1
      fi
      ;;
  esac
fi
for storage_command in $storage_commands; do
  if ! command -v "$storage_command" >/dev/null 2>&1; then
    echo "Storage dependency is still unavailable after offline package installation: $storage_command" >&2
    exit 1
  fi
done
install -d -m 0750 /opt/tram-agent /etc/tram-agent /var/log/tram-agent
install -d -m 0700 /var/lib/tram-agent/inbox
systemctl stop tram-agent.service >/dev/null 2>&1 || true
install -m 0755 "$artifact" /opt/tram-agent/tram-agent
install -m 0644 "$script_dir/VERSION" /opt/tram-agent/VERSION
install -m 0644 "$script_dir/tram-agent.service" /etc/systemd/system/tram-agent.service
if command -v restorecon >/dev/null 2>&1; then
  restorecon -RF /opt/tram-agent /etc/tram-agent /var/lib/tram-agent /var/log/tram-agent /etc/systemd/system/tram-agent.service >/dev/null 2>&1 || true
fi
systemctl daemon-reload

if systemctl list-unit-files ssh.service 2>/dev/null | grep -q '^ssh\.service'; then
  systemctl enable --now ssh
elif systemctl list-unit-files sshd.service 2>/dev/null | grep -q '^sshd\.service'; then
  systemctl enable --now sshd
else
  echo "WARNING: OpenSSH Server is not installed. Agent management works, but SSH sessions require the OS-provided sshd package." >&2
fi
if ! command -v clamscan >/dev/null 2>&1; then
  echo "WARNING: endpoint ClamAV is missing. Secure file delivery remains fail-closed until an approved scanner and signatures are installed." >&2
fi

if [ "$identity_state" = "enrolled" ]; then
  systemctl enable tram-agent.service
  systemctl restart tram-agent.service
  echo "Existing Agent identity preserved; Agent upgraded and restarted without bootstrap enrollment."
elif [ -n "$bootstrap_source" ]; then
  if [ ! -f "$bootstrap_source" ]; then
    echo "Bootstrap file does not exist" >&2
    exit 1
  fi
  install -m 0600 "$bootstrap_source" /etc/tram-agent/bootstrap.json
  cleanup_bootstrap() { rm -f /etc/tram-agent/bootstrap.json; }
  trap cleanup_bootstrap EXIT HUP INT TERM
  /opt/tram-agent/tram-agent \
    --config /etc/tram-agent/agent.json \
    --log-file /var/log/tram-agent/agent.log \
    bootstrap --file /etc/tram-agent/bootstrap.json
  cleanup_bootstrap
  trap - EXIT HUP INT TERM
  systemctl enable --now tram-agent.service
  echo "Agent enrolled and started without downloading Python or pip packages."
else
  systemctl try-restart tram-agent.service
  echo "Agent installed. Enroll it, then enable tram-agent.service."
fi
