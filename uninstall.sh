#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Uninstall systemd service.
# Usage: sudo ./uninstall.sh

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo $0"
  exit 1
fi

systemctl stop proxy-server 2>/dev/null || true
systemctl disable proxy-server 2>/dev/null || true
rm -f /etc/systemd/system/proxy-server.service
rm -f /usr/local/bin/proxy-server
systemctl daemon-reload
echo "[+] Removed proxy-server service (config kept at /etc/proxy-server/proxy.env)"
echo "    Remove config manually: sudo rm -rf /etc/proxy-server"
