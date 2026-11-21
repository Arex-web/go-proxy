#!/bin/sh
set -eu
cd "$(dirname "$0")"
echo "[*] Building proxy-server (release)..."
cargo build --release
cp target/release/proxy-server ./proxy-server
ls -lh proxy-server
echo "[+] Build done: ./proxy-server"