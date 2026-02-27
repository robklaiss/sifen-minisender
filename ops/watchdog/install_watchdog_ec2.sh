#!/usr/bin/env bash
set -euo pipefail

# Must run on EC2 with sudo
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "ERROR: run with sudo: sudo bash ops/watchdog/install_watchdog_ec2.sh"
  exit 1
fi

APP_DIR="/opt/sifen-minisender"
SRC_DIR="$APP_DIR/ops/watchdog"

# Ensure curl exists (needed for health checks)
if ! command -v curl >/dev/null 2>&1; then
  echo "Installing curl..."
  apt-get update
  apt-get install -y curl
fi

install -m 0755 "$SRC_DIR/sifen_watchdog.sh" /usr/local/bin/sifen_watchdog.sh
install -m 0644 "$SRC_DIR/sifen-watchdog.service" /etc/systemd/system/sifen-watchdog.service
install -m 0644 "$SRC_DIR/sifen-watchdog.timer" /etc/systemd/system/sifen-watchdog.timer

systemctl daemon-reload
systemctl enable --now sifen-watchdog.timer

echo
echo "OK installed. Status:"
systemctl status sifen-watchdog.timer --no-pager || true
echo
echo "Recent runs:"
journalctl -u sifen-watchdog.service -n 20 --no-pager || true
