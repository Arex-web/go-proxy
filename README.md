# SOCKS5 + HTTP + MTProto Proxy Server (Go + Bash)

A single-binary proxy that turns your Linux server into a
**SOCKS5 + HTTP + MTProto (Telegram) proxy on one port** (protocol
auto-detected), with optional username/password auth and a bash installer +
systemd unit.

Telegram MTProto support is powered by
[mtg](https://github.com/9seconds/mtg) (`mtglib`), a mature, fast
obfuscated2/fake-TLS implementation with domain fronting and anti-replay.

## Build & Run (quick)

```bash
./build.sh
./run.sh                                     # reads .env (or defaults)
./run.sh 0.0.0.0:1080 myuser mypass -v       # with auth + verbose
```

### Config via `.env` (recommended)
Copy `.env.example` → `.env` and edit:
```ini
PROXY_ADDR=0.0.0.0:1080      # host:port, or use PROXY_PORT=1080 / PORT=1080
PROXY_USERNAME=myuser
PROXY_PASSWORD=change-me-strong-password
# Telegram MTProto (optional, fake-TLS "ee" secret):
# MTPROTO_SECRET=ee<32 hex><domain hex>
# MTPROTO_ADDR=0.0.0.0:8443  # optional dedicated MTProto-only listener
```
`./run.sh` and `./proxy-server` load `.env` automatically.
Priority: flags > exported env > `.env` > defaults.
See [`.env.example`](.env.example).

## MTProto (Telegram)

Generate a fake-TLS secret (the domain is the fronting/SNI host):

```bash
./proxy-server -gen-secret                       # uses www.google.com
./proxy-server -gen-secret -gen-host example.com
```

Add it to `.env` as `MTPROTO_SECRET=ee...` and restart. MTProto is then
accepted on the **same port** as SOCKS5/HTTP, or on a dedicated port via
`MTPROTO_ADDR`. Share the printed `tg://proxy?...` link with clients.

Only fake-TLS (`ee`) secrets are supported (this is what mtg implements).
Multiple secrets may be comma-separated.

## Install as a System Service

```bash
sudo ./install.sh
sudo ./install.sh 0.0.0.0:1080 myuser 'strong-password'
sudo ./install.sh 0.0.0.0:1080 myuser 'strong-password' ee<secret>
```

Creates `/usr/local/bin/proxy-server` + `proxy-server.service` (auto-start, restart on failure).

```bash
journalctl -u proxy-server -f    # logs
sudo systemctl restart proxy-server
```

## Usage

```bash
# HTTP proxy
curl -x http://myuser:mypass@SERVER:1080 https://example.com
curl -x http://myuser:mypass@SERVER:1080 http://example.com

# SOCKS5 proxy
curl -x socks5h://myuser:mypass@SERVER:1080 https://example.com
```

> `socks5h://` (not `socks5://`) so DNS is resolved remotely.

Run the bundled tester:

```bash
./test.sh
./test.sh SERVER:1080 myuser mypass
```

## Configuration

| Flag | Env / `.env` | Default |
|------|---------------|---------|
| `-addr` | `PROXY_ADDR` / `PROXY_PORT` / `PORT` | `0.0.0.0:1080` |
| `-username` | `PROXY_USERNAME` | _(empty = no auth)_ |
| `-password` | `PROXY_PASSWORD` | |
| `-timeout` | — | `30s` |
| `-mtproto-secret` | `MTPROTO_SECRET` | _(empty = MTProto off)_ |
| `-mtproto-addr` | `MTPROTO_ADDR` | _(shared port only)_ |
| `-gen-secret` | — | generate a secret and exit |
| `-gen-host` | `MTPROTO_FRONTING_HOST` | `www.google.com` |
| `-v` | — | verbose logging |

## Features

- **One port, three protocols** — first bytes select SOCKS5 (`0x05`),
  HTTP (method letters), or MTProto (fake TLS `0x16` / obfuscated2).
- SOCKS5 `CONNECT` + `UDP ASSOCIATE` (RFC 1928), user/pass auth (RFC 1929).
- HTTP `CONNECT` tunnels (HTTPS) + absolute-URI forwarding (plain HTTP).
- MTProto via [mtg](https://github.com/9seconds/mtg): obfuscated2 + fake TLS,
  domain fronting, anti-replay, direct DC connections.
- Constant-time credential comparison, configurable dial timeout.

## Uninstall

```bash
sudo ./uninstall.sh
```

## Files

```
main.go        CLI flags + unified listener (SOCKS5/HTTP/MTProto)
socks5.go      SOCKS5 server (CONNECT / UDP ASSOCIATE)
httpproxy.go   HTTP forward proxy (CONNECT / GET forwarding)
mtproto.go     MTProto (Telegram) via mtg mtglib + protocol detection
config.go      Auth + timeout + MTProto config
build.sh       go build
run.sh         quick dev run
install.sh     systemd installer (run with sudo)
uninstall.sh   remove service
test.sh        curl smoke-tests
```