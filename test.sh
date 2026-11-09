#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Test a running proxy (SOCKS5 + HTTP + auth).
# Usage:
#   ./test.sh                          # assumes local, no auth
#   ./test.sh 127.0.0.1:1080 user pass # custom
#   PROXY=127.0.0.1:1080 U=u P=p ./test.sh

ADDR="${1:-${PROXY:-127.0.0.1:1080}}"
USER="${2:-${PROXY_USERNAME:-}}"
PASS="${3:-${PROXY_PASSWORD:-}}"

AUTH=""
[[ -n "$USER" ]] && AUTH="${USER}:${PASS}@"

echo "Target: ${ADDR} (auth: ${USER:+yes})"
echo

check() {
  local label="$1"; shift
  local expect="$1"; shift
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 "$@" https://example.com 2>/dev/null || true)
  # Normalize: curl prints 000 on transport failure
  code="${code:-000}"
  code="$(echo "$code" | tr -d ' \n')"
  if [[ "$code" == "$expect" ]]; then
    echo "  [PASS] $label -> $code"
  else
    echo "  [FAIL] $label -> $code (expected $expect)"
  fi
}

echo "== HTTP proxy =="
check "HTTP plain   " "200" -x "http://${AUTH}${ADDR}"
check "HTTP CONNECT " "200" -x "http://${AUTH}${ADDR}"

echo "== SOCKS5 proxy =="
check "SOCKS5       " "200" -x "socks5h://${AUTH}${ADDR}"

if [[ -n "$USER" ]]; then
  echo "== Auth enforcement (wrong password should fail) =="
  check "HTTP badpass " "000" -x "http://${USER}:wrong@${ADDR}"
  check "SOCKS5 badpass" "000" -x "socks5h://${USER}:wrong@${ADDR}"
fi

echo
echo "Done."
