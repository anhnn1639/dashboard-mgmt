#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo sh agent/install-linux.sh" >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip ca-certificates openssh-server
fi

for required_command in python3 install systemctl; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "Missing required command: $required_command" >&2
    exit 1
  fi
done

install -d -m 0750 /opt/tram-agent /etc/tram-agent /var/log/tram-agent
python3 -m venv /opt/tram-agent/venv
/opt/tram-agent/venv/bin/pip install --no-cache-dir --upgrade pip
/opt/tram-agent/venv/bin/pip install --no-cache-dir -r "$script_dir/requirements.txt"
install -m 0750 "$script_dir/tram_agent.py" /opt/tram-agent/tram_agent.py
install -m 0644 "$script_dir/tram-agent.service" /etc/systemd/system/tram-agent.service
systemctl daemon-reload

if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
  systemctl enable --now ssh
fi
systemctl try-restart tram-agent.service

echo "Installed. Enroll with:"
echo "  sudo /opt/tram-agent/venv/bin/python /opt/tram-agent/tram_agent.py enroll --server http://ops.example.com --token 'ONE_TIME_TOKEN'"
echo "Then start: sudo systemctl enable --now tram-agent"
