#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Install proxy-server as a systemd service.
# Usage:
#   sudo ./install.sh
#   sudo ./install.sh 0.0.0.0:1080 myuser 'strong-password'
#   sudo PROXY_ADDR=0.0.0.0:1080 ./install.sh
#   (also reads .env if present)
#
# Creates: /usr/local/bin/proxy-server, /etc/proxy-server/proxy.env,
#          /etc/systemd/system/proxy-server.service

# Load .env for defaults (flags still win)
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env 2>/dev/null || true
  set +a
fi

ADDR="${1:-${PROXY_ADDR:-0.0.0.0:1080}}"
USER="${2:-${PROXY_USERNAME:-}}"
PASS="${3:-${PROXY_PASSWORD:-}}"

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo $0 $*"
  exit 1
fi

echo "[*] Building..."
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o proxy-server .
echo "[*] Installing binary to /usr/local/bin/proxy-server"
install -m 0755 ./proxy-server /usr/local/bin/proxy-server

echo "[*] Writing config /etc/proxy-server/proxy.env"
mkdir -p /etc/proxy-server
if [[ -n "$USER" ]]; then
  cat > /etc/proxy-server/proxy.env <<EOF
PROXY_ADDR=$ADDR
PROXY_USERNAME=$USER
PROXY_PASSWORD=$PASS
EOF
else
  cat > /etc/proxy-server/proxy.env <<EOF
PROXY_ADDR=$ADDR
# PROXY_USERNAME= 
# PROXY_PASSWORD=
EOF
  echo "    (no auth configured — public proxy. Re-run with user/pass to protect it.)"
fi
chmod 600 /etc/proxy-server/proxy.env

echo "[*] Installing systemd unit /etc/systemd/system/proxy-server.service"
cat > /etc/systemd/system/proxy-server.service <<'UNIT'
[Unit]
Description=SOCKS5+HTTP Proxy Server (Go)
After=network.target
Wants=network.target

[Service]
Type=simple
EnvironmentFile=-/etc/proxy-server/proxy.env
ExecStart=/usr/local/bin/proxy-server
Restart=on-failure
RestartSec=2
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable proxy-server
systemctl restart proxy-server

echo "[+] Installed. Status:"
systemctl status proxy-server --no-pager -l | head -n 15
echo
echo "Logs:    journalctl -u proxy-server -f"
echo "Test:    $0" | sed 's|.*|curl -x … (see ./test.sh)|'
if [[ -n "$USER" ]]; then
  echo "  curl -x http://${USER}:${PASS}@${ADDR} https://example.com"
  echo "  curl -x socks5h://${USER}:${PASS}@${ADDR} https://example.com"
else
  echo "  curl -x http://${ADDR} https://example.com"
  echo "  curl -x socks5h://${ADDR} https://example.com"
fi
echo
echo "Firewall (if ufw): sudo ufw allow ${ADDR##*:}/tcp"
echo "Firewall (if firewalld): sudo firewall-cmd --permanent --add-port=${ADDR##*:}/tcp && sudo firewall-cmd --reload"
