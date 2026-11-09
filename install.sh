#!/bin/sh
set -eu
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

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env 2>/dev/null || true
  set +a
fi

if [ -n "${1:-}" ]; then
  ADDR="$1"
elif [ -n "${PROXY_ADDR:-}" ]; then
  ADDR="$PROXY_ADDR"
elif [ -n "${PROXY_PORT:-}" ]; then
  ADDR="0.0.0.0:$PROXY_PORT"
elif [ -n "${PORT:-}" ]; then
  ADDR="0.0.0.0:$PORT"
else
  ADDR="0.0.0.0:1080"
fi
case "$ADDR" in
  *:*) ;;
  *) ADDR="0.0.0.0:$ADDR" ;;
esac
USER="${2:-${PROXY_USERNAME:-}}"
PASS="${3:-${PROXY_PASSWORD:-}}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: sudo $0 $*"
  exit 1
fi

echo "[*] Building..."
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o proxy-server .
echo "[*] Installing binary to /usr/local/bin/proxy-server"
install -m 0755 ./proxy-server /usr/local/bin/proxy-server

echo "[*] Writing config /etc/proxy-server/proxy.env"
mkdir -p /etc/proxy-server
if [ -n "$USER" ]; then
  printf 'PROXY_ADDR=%s\nPROXY_USERNAME=%s\nPROXY_PASSWORD=%s\n' "$ADDR" "$USER" "$PASS" > /etc/proxy-server/proxy.env
else
  printf 'PROXY_ADDR=%s\n# PROXY_USERNAME=\n# PROXY_PASSWORD=\n' "$ADDR" > /etc/proxy-server/proxy.env
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
if [ -n "$USER" ]; then
  echo "  curl -x http://${USER}:${PASS}@${ADDR} https://example.com"
  echo "  curl -x socks5h://${USER}:${PASS}@${ADDR} https://example.com"
else
  echo "  curl -x http://${ADDR} https://example.com"
  echo "  curl -x socks5h://${ADDR} https://example.com"
fi
echo
echo "Firewall (if ufw): sudo ufw allow $(echo "$ADDR" | cut -d: -f2)/tcp"
echo "Firewall (if firewalld): sudo firewall-cmd --permanent --add-port=$(echo "$ADDR" | cut -d: -f2)/tcp && sudo firewall-cmd --reload"
