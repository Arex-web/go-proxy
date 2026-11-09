#!/bin/sh
set -eu
cd "$(dirname "$0")"

# Quick dev run — no systemd needed.
# Loads .env automatically (if present). Flags override .env.
# Runs with both sh and bash.
# Usage:
#   ./run.sh                                   # reads .env (or defaults)
#   ./run.sh 0.0.0.0:8080 myuser mypass -v    # args override .env

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env 2>/dev/null || true
  set +a
fi

# Positional args override .env
# Also accept PROXY_PORT / PORT aliases and bare ports (26398 -> 0.0.0.0:26398)
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
  *:*) ;;  # host:port already
  *) ADDR="0.0.0.0:$ADDR" ;;
esac
USER="${2:-${PROXY_USERNAME:-}}"
PASS="${3:-${PROXY_PASSWORD:-}}"
if [ "$#" -gt 3 ]; then
  shift 3
else
  shift "$#"
fi

if [ ! -x ./proxy-server ]; then
  echo "[*] proxy-server not found, building..."
  ./build.sh
fi

echo "[*] Starting on ${ADDR} (.env: $([ -f .env ] && echo ".env" || echo "none"))"
if [ -n "$USER" ]; then
  echo "    SOCKS5: curl -x socks5h://${USER}:${PASS}@${ADDR} https://example.com"
  echo "    HTTP:   curl -x http://${USER}:${PASS}@${ADDR} https://example.com"
  exec ./proxy-server -addr "$ADDR" -username "$USER" -password "$PASS" "$@"
else
  echo "    SOCKS5: curl -x socks5h://${ADDR} https://example.com"
  echo "    HTTP:   curl -x http://${ADDR} https://example.com"
  exec ./proxy-server -addr "$ADDR" "$@"
fi
