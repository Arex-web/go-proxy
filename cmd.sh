#!/bin/sh
set -eu
cd "$(dirname "$0")"

# Single entry point for build, install and run.
#
# Usage:
#   ./cmd.sh                                   # build, then run (reads .env)
#   ./cmd.sh build                             # build only
#   ./cmd.sh run [addr] [user] [pass] [flags]  # run (builds if binary is missing)
#   sudo ./cmd.sh install [addr] [user] [pass] [ee-secret] [mtproto-addr]
#   ./cmd.sh test [addr] [user] [pass]         # curl smoke-tests a running proxy
#   ./cmd.sh -gen-secret [-gen-host host]      # build, then generate a secret
#
# Positional arguments override .env. A bare port (1080) means 0.0.0.0:1080.
# Extra flags are forwarded to the proxy binary.

COMMAND="${1:-all}"
[ "$#" -gt 0 ] && shift || true

load_env() {
  if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env 2>/dev/null || true
    set +a
  fi
}

build() {
  echo "[*] Building proxy-server..."
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o proxy-server .
  echo "[+] Build done: ./proxy-server"
}

# Uses $1 as the listen address, falling back to PROXY_ADDR / PROXY_PORT /
# PORT and finally 0.0.0.0:1080. Fills ADDR.
resolve_addr() {
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
}

run_proxy() {
  load_env
  resolve_addr "${1:-}"
  USERNAME="${2:-${PROXY_USERNAME:-}}"
  PASSWORD="${3:-${PROXY_PASSWORD:-}}"
  if [ "$#" -gt 3 ]; then
    shift 3
  else
    shift "$#"
  fi

  [ -x ./proxy-server ] || build

  echo "[*] Starting on ${ADDR} (.env: $([ -f .env ] && echo "yes" || echo "none"))"
  if [ -n "$USERNAME" ]; then
    echo "    SOCKS5: curl -x socks5h://${USERNAME}:${PASSWORD}@${ADDR} https://example.com"
    echo "    HTTP:   curl -x http://${USERNAME}:${PASSWORD}@${ADDR} https://example.com"
  else
    echo "    SOCKS5: curl -x socks5h://${ADDR} https://example.com"
    echo "    HTTP:   curl -x http://${ADDR} https://example.com"
  fi
  if [ -n "${MTPROTO_SECRET:-}" ]; then
    echo "    MTProto: enabled on ${ADDR}${MTPROTO_ADDR:+ (and ${MTPROTO_ADDR})}"
  else
    echo "    MTProto: disabled (generate a secret: ./cmd.sh -gen-secret)"
  fi

  if [ -n "$USERNAME" ]; then
    exec ./proxy-server -addr "$ADDR" -username "$USERNAME" -password "$PASSWORD" "$@"
  else
    exec ./proxy-server -addr "$ADDR" "$@"
  fi
}

install_service() {
  load_env
  resolve_addr "${1:-}"
  USERNAME="${2:-${PROXY_USERNAME:-}}"
  PASSWORD="${3:-${PROXY_PASSWORD:-}}"
  MTP_SECRET="${4:-${MTPROTO_SECRET:-}}"
  MTP_ADDR="${5:-${MTPROTO_ADDR:-}}"
  MTP_PORT="$(echo "$ADDR" | cut -d: -f2)"

  if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo $0 install $*"
    exit 1
  fi

  build

  echo "[*] Installing binary to /usr/local/bin/proxy-server"
  install -m 0755 ./proxy-server /usr/local/bin/proxy-server

  echo "[*] Writing config /etc/proxy-server/proxy.env"
  mkdir -p /etc/proxy-server

  # put_env only writes a line when a value is set, so unset options keep
  # their mtg defaults instead of being pinned in the file.
  put_env() {
    [ -n "$2" ] && printf '%s=%s\n' "$1" "$2"
  }

  {
    printf 'PROXY_ADDR=%s\n' "$ADDR"
    if [ -n "$USERNAME" ]; then
      printf 'PROXY_USERNAME=%s\nPROXY_PASSWORD=%s\n' "$USERNAME" "$PASSWORD"
    else
      printf '# PROXY_USERNAME=\n# PROXY_PASSWORD=\n'
    fi
    if [ -n "$MTP_SECRET" ]; then
      printf 'MTPROTO_SECRET=%s\n' "$MTP_SECRET"
    else
      printf '# MTPROTO_SECRET=ee<secret>    # generate: ./cmd.sh -gen-secret\n'
    fi
    if [ -n "$MTP_ADDR" ]; then
      printf 'MTPROTO_ADDR=%s\n' "$MTP_ADDR"
    else
      printf '# MTPROTO_ADDR=0.0.0.0:8443   # optional extra MTProto-only port\n'
    fi

    put_env PROXY_TIMEOUT "${PROXY_TIMEOUT:-}"
    put_env PROXY_VERBOSE "${PROXY_VERBOSE:-}"
    put_env MTPROTO_CONCURRENCY "${MTPROTO_CONCURRENCY:-}"
    put_env MTPROTO_FRONTING_HOST "${MTPROTO_FRONTING_HOST:-}"
    put_env MTPROTO_FRONTING_PORT "${MTPROTO_FRONTING_PORT:-}"
    put_env MTPROTO_PREFER_IP "${MTPROTO_PREFER_IP:-}"
    put_env MTPROTO_ALLOW_FALLBACK_DC "${MTPROTO_ALLOW_FALLBACK_DC:-}"
    put_env MTPROTO_AUTOUPDATE "${MTPROTO_AUTOUPDATE:-}"
    put_env MTPROTO_IDLE_TIMEOUT "${MTPROTO_IDLE_TIMEOUT:-}"
    put_env MTPROTO_HANDSHAKE_TIMEOUT "${MTPROTO_HANDSHAKE_TIMEOUT:-}"
    put_env MTPROTO_TOLERATE_SKEW "${MTPROTO_TOLERATE_SKEW:-}"
    put_env MTPROTO_DOPPELGANGER_DRS "${MTPROTO_DOPPELGANGER_DRS:-}"
  } > /etc/proxy-server/proxy.env
  chmod 600 /etc/proxy-server/proxy.env

  if [ -z "$USERNAME" ]; then
    echo "    (no auth configured - public proxy. Re-run with user/pass to protect it.)"
  fi
  if [ -z "$MTP_SECRET" ]; then
    echo "    (MTProto disabled. Set MTPROTO_SECRET=ee... or pass it as the 4th argument.)"
  fi

  echo "[*] Installing systemd unit /etc/systemd/system/proxy-server.service"
  cat > /etc/systemd/system/proxy-server.service <<'UNIT'
[Unit]
Description=SOCKS5+HTTP+MTProto Proxy Server (Go + mtg)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/proxy-server/proxy.env
ExecStart=/usr/local/bin/proxy-server
Restart=on-failure
RestartSec=2
# Allows listening on 443/80 as an unprivileged user.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
# Hardening (mtg receives UDP nowhere, and dials out to Telegram only).
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
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
  if [ -n "$USERNAME" ]; then
    echo "  curl -x http://${USERNAME}:${PASSWORD}@${ADDR} https://example.com"
    echo "  curl -x socks5h://${USERNAME}:${PASSWORD}@${ADDR} https://example.com"
  else
    echo "  curl -x http://${ADDR} https://example.com"
    echo "  curl -x socks5h://${ADDR} https://example.com"
  fi
  if [ -n "$MTP_SECRET" ]; then
    echo "  Telegram MTProto: server=SERVER_IP port=${MTP_PORT} secret=${MTP_SECRET}"
    echo "  tg://proxy?server=SERVER_IP&port=${MTP_PORT}&secret=${MTP_SECRET}"
    echo "  https://t.me/proxy?server=SERVER_IP&port=${MTP_PORT}&secret=${MTP_SECRET}"
    if [ -n "$MTP_ADDR" ]; then
      echo "  Also listening for MTProto on ${MTP_ADDR}"
    fi
  fi
  echo
  echo "Firewall (if ufw): sudo ufw allow ${MTP_PORT}/tcp"
  echo "Firewall (if firewalld): sudo firewall-cmd --permanent --add-port=${MTP_PORT}/tcp && sudo firewall-cmd --reload"
}

case "$COMMAND" in
  build)
    build
    ;;
  run)
    run_proxy "$@"
    ;;
  install)
    install_service "$@"
    ;;
  test)
    exec ./test.sh "$@"
    ;;
  all)
    build
    run_proxy "$@"
    ;;
  -h|--help|help)
    sed -n '5,15p' "$0"
    ;;
  -*)
    # A bare flag (for example -gen-secret) belongs to the binary.
    build
    exec ./proxy-server "$COMMAND" "$@"
    ;;
  *)
    # Treat it as a run argument: build first, then run.
    build
    run_proxy "$COMMAND" "$@"
    ;;
esac
