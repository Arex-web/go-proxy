#!/bin/sh
set -eu
cd "$(dirname "$0")"

# Smoke-test a running proxy (SOCKS5 + HTTP + auth).
# Usage:
#   ./test.sh                          # assumes local, no auth
#   ./test.sh 127.0.0.1:1080 user pass # custom
#   PROXY=127.0.0.1:1080 PROXY_USERNAME=u PROXY_PASSWORD=p ./test.sh
#
# Exits non-zero if any check fails. MTProto itself cannot be checked with
# curl; open the tg:// link printed by the server in Telegram instead.

ADDR="${1:-${PROXY:-127.0.0.1:1080}}"
USERNAME="${2:-${PROXY_USERNAME:-}}"
PASSWORD="${3:-${PROXY_PASSWORD:-}}"

AUTH=""
if [ -n "$USERNAME" ]; then
  AUTH="${USERNAME}:${PASSWORD}@"
fi

FAILED=0

echo "Target: ${ADDR} (auth: $([ -n "$USERNAME" ] && echo yes || echo no))"
echo

check() {
  _label="$1"; shift
  _expect="$1"; shift
  _url="$1"
  _code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 -x "$_url" https://example.com 2>/dev/null || true)
  _code=$(echo "${_code:-000}" | tr -d ' \n')
  if [ "$_code" = "$_expect" ]; then
    echo "  [PASS] $_label -> $_code"
  else
    echo "  [FAIL] $_label -> $_code (expected $_expect)"
    FAILED=$((FAILED + 1))
  fi
}

echo "== HTTP proxy =="
check "HTTP plain   " "200" "http://${AUTH}${ADDR}"
check "HTTP CONNECT " "200" "http://${AUTH}${ADDR}"

echo "== SOCKS5 proxy =="
check "SOCKS5       " "200" "socks5h://${AUTH}${ADDR}"

if [ -n "$USERNAME" ]; then
  echo "== Auth enforcement (wrong password should fail) =="
  check "HTTP badpass " "000" "http://${USERNAME}:wrong@${ADDR}"
  check "SOCKS5 badpass" "000" "socks5h://${USERNAME}:wrong@${ADDR}"
fi

echo
if [ "$FAILED" -ne 0 ]; then
  echo "FAILED: ${FAILED} check(s)."
  exit 1
fi
echo "Done."
