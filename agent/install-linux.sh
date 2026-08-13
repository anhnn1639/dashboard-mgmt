#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash agent/install-linux.sh" >&2
  exit 1
fi

install -d -m 0750 /opt/tram-agent /etc/tram-agent /var/log/tram-agent
python3 -m venv /opt/tram-agent/venv
/opt/tram-agent/venv/bin/pip install --no-cache-dir -r "$(dirname "$0")/requirements.txt"
install -m 0750 "$(dirname "$0")/tram_agent.py" /opt/tram-agent/tram_agent.py
install -m 0644 "$(dirname "$0")/tram-agent.service" /etc/systemd/system/tram-agent.service
systemctl daemon-reload

echo "Installed. Enroll with:"
echo "  sudo /opt/tram-agent/venv/bin/python /opt/tram-agent/tram_agent.py enroll --server http://ops.example.com --token 'ONE_TIME_TOKEN'"
echo "Then start: sudo systemctl enable --now tram-agent"
