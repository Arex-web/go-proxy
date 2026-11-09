# SOCKS5 + HTTP Proxy Server (Go + Bash)

A single-binary, zero-dependency proxy that turns your Linux server into a
**SOCKS5 + HTTP forward proxy on one port** (protocol auto-detected),
with optional username/password auth and a bash installer + systemd unit.

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
```
`./run.sh` and `./proxy-server` load `.env` automatically.
Priority: flags > exported env > `.env` > defaults.
See [`.env.example`](.env.example).

## Install as a System Service

```bash
sudo ./install.sh
sudo ./install.sh 0.0.0.0:1080 myuser 'strong-password'
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
| `-v` | — | verbose logging |

## Features

- **One port, two protocols** — first byte `0x05` → SOCKS5, else HTTP.
- SOCKS5 `CONNECT` + `UDP ASSOCIATE` (RFC 1928), user/pass auth (RFC 1929).
- HTTP `CONNECT` tunnels (HTTPS) + absolute-URI forwarding (plain HTTP).
- Constant-time credential comparison, configurable dial timeout.

## Uninstall

```bash
sudo ./uninstall.sh
```

## Files

```
main.go        CLI flags + auto-detect listener
socks5.go      SOCKS5 server (CONNECT / UDP ASSOCIATE)
httpproxy.go   HTTP forward proxy (CONNECT / GET forwarding)
config.go      Auth + timeout config
build.sh       go build
run.sh         quick dev run
install.sh     systemd installer (run with sudo)
uninstall.sh   remove service
test.sh        curl smoke-tests
```
