#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Quick dev run — no systemd needed.
# Loads .env automatically (if present). Flags override .env.
# Usage:
#   ./run.sh                                   # reads .env (or defaults)
#   ./run.sh 0.0.0.0:8080 myuser mypass -v    # args override .env
#   PROXY_ADDR=... ./run.sh                   # exported env overrides .env

# Load .env (don't override already-exported vars)
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env 2>/dev/null || true
  set +a
fi

ADDR="${1:-${PROXY_ADDR:-0.0.0.0:1080}}"
USER="${2:-${PROXY_USERNAME:-}}"
PASS="${3:-${PROXY_PASSWORD:-}}"
shift $(( $# > 3 ? 3 : $# )) 2>/dev/null || true
EXTRA=("$@")

if [[ ! -x ./proxy-server ]]; then
  echo "[*] proxy-server not found, building..."
  ./build.sh
fi

ARGS=(-addr "$ADDR")
[[ -n "$USER" ]] && ARGS+=(-username "$USER" -password "$PASS")
[[ ${#EXTRA[@]} -gt 0 ]] && ARGS+=("${EXTRA[@]}")

echo "[*] Starting on ${ADDR} (.env: $([[ -f .env ]] && echo ".env" || echo "none"))"
echo "    SOCKS5: curl -x socks5h://${USER:+${USER}:${PASS}@}${ADDR} https://example.com"
echo "    HTTP:   curl -x http://${USER:+${USER}:${PASS}@}${ADDR} https://example.com"
exec ./proxy-server "${ARGS[@]}"
