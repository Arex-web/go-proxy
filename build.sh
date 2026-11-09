#!/bin/sh
set -eu
cd "$(dirname "$0")"
echo "[*] Building proxy-server..."
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o proxy-server .
ls -lh proxy-server
echo "[+] Build done: ./proxy-server"
