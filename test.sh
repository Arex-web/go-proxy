#!/bin/sh
set -eu
cd "$(dirname "$0")"

# Test a running proxy (SOCKS5 + HTTP + auth).
# Usage:
#   ./test.sh                          # assumes local, no auth
#   ./test.sh 127.0.0.1:1080 user pass # custom
#   PROXY=127.0.0.1:1080 PROXY_USERNAME=u PROXY_PASSWORD=p ./test.sh

ADDR="${1:-${PROXY:-127.0.0.1:1080}}"
USER="${2:-${PROXY_USERNAME:-}}"
PASS="${3:-${PROXY_PASSWORD:-}}"

AUTH=""
if [ -n "$USER" ]; then
  AUTH="${USER}:${PASS}@"
fi

echo "Target: ${ADDR} (auth: $([ -n "$USER" ] && echo yes || echo no))"
echo

check() {
  _label="$1"; shift
  _expect="$1"; shift
  _code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 -x "$1" https://example.com 2>/dev/null || true)
  # Normalize: curl prints 000 on transport failure
  if [ -z "$_code" ]; then _code="000"; fi
  _code=$(echo "$_code" | tr -d ' \n')
  if [ "$_code" = "$_expect" ]; then
    echo "  [PASS] $_label -> $_code"
  else
    echo "  [FAIL] $_label -> $_code (expected $_expect)"
  fi
}

echo "== HTTP proxy =="
check "HTTP plain   " "200" "http://${AUTH}${ADDR}"
check "HTTP CONNECT " "200" "http://${AUTH}${ADDR}"

echo "== SOCKS5 proxy =="
check "SOCKS5       " "200" "socks5h://${AUTH}${ADDR}"

if [ -n "$USER" ]; then
  echo "== Auth enforcement (wrong password should fail) =="
  check "HTTP badpass " "000" "http://${USER}:wrong@${ADDR}"
  check "SOCKS5 badpass" "000" "socks5h://${USER}:wrong@${ADDR}"
fi

echo
echo "Done."
