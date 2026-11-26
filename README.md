# SOCKS5 + HTTP + MTProto Proxy Server (Go + Bash)

A single-binary proxy that turns your Linux server into a
**SOCKS5 + HTTP + MTProto (Telegram) proxy on one port** (protocol
auto-detected), with optional username/password auth and a bash installer +
systemd unit.

Telegram MTProto support is powered by
[mtg](https://github.com/9seconds/mtg) (`mtglib`), the same engine that runs the
mtg proxy server: fake TLS, domain fronting, anti-replay, direct DC
connections. Every MTProto knob here maps 1:1 to `mtglib.ProxyOpts`, so mtg's
documentation applies directly.

## Build, Install & Run (one script)

`cmd.sh` is the only script: it builds, installs as a service and runs.

```bash
./cmd.sh                                    # build, then run (reads .env)
./cmd.sh build                              # build only
./cmd.sh run                                # run only (builds if needed)
./cmd.sh run 0.0.0.0:1080 myuser mypass -v  # with auth + verbose
./cmd.sh -gen-secret                        # build, then print a new secret
sudo ./cmd.sh install                       # build + install systemd service
./cmd.sh test 127.0.0.1:1080 user pass      # curl smoke-tests a running proxy
```

### Config via `.env` (recommended)

```bash
cp proxy.env.example .env    # then edit
```

```ini
PROXY_ADDR=0.0.0.0:1080      # host:port, or use PROXY_PORT=1080 / PORT=1080
PROXY_USERNAME=myuser
PROXY_PASSWORD=change-me-strong-password
# Telegram MTProto (optional, fake-TLS "ee" secret):
MTPROTO_SECRET=ee<32 hex><domain hex>
# MTPROTO_ADDR=0.0.0.0:8443  # optional dedicated MTProto-only listener
```

`./cmd.sh run` and `./proxy-server` load `.env` automatically.
Priority: flags > exported env > `.env` > defaults.

## MTProto (Telegram)

Generate a fake-TLS secret (the domain is the fronting/SNI host):

```bash
./cmd.sh -gen-secret                            # uses www.google.com
./cmd.sh -gen-secret -gen-host example.com
```

The command prints the secret in hex and base64, the `.env` line, and both
share links (`tg://proxy?...` and `https://t.me/proxy?...`).

Add `MTPROTO_SECRET=ee...` to `.env` and restart. MTProto is then accepted on
the **same port** as SOCKS5/HTTP, and optionally on a dedicated port via
`MTPROTO_ADDR`. Multiple secrets may be comma-separated; duplicates are
dropped.

### How the port behaves

- **Fake TLS only.** mtg accepts only `ee...` fake-TLS secrets (plain
  obfuscated2 and old `dd` secrets were removed from mtg). A secret generated
  here is always `ee...`.
- **Domain fronting.** A TLS client that does not authenticate with any
  configured secret is forwarded to the fronting host, so probing the port
  returns a normal HTTPS site instead of a refused connection. This is why the
  shared port can also be used as a plain HTTPS endpoint for the fronting
  domain.
- **Anti-replay.** One mtg stable-bloom cache is shared by all secrets, so a
  replayed ClientHello is rejected no matter which secret it claims.
- **Concurrency.** Each secret gets an mtg proxy with its own stream limit
  (`MTPROTO_CONCURRENCY`, default 4096); excess connections are dropped.

### MTProto options

| Flag | Env / `.env` | Default | mtg equivalent |
|------|--------------|---------|----------------|
| `-mtproto-secret` | `MTPROTO_SECRET` | _(off)_ | `secret` |
| `-mtproto-addr` | `MTPROTO_ADDR` | _(shared port only)_ | `bind-to` (extra) |
| `-mtproto-concurrency` | `MTPROTO_CONCURRENCY` | `4096` | `concurrency` |
| `-mtproto-fronting-port` | `MTPROTO_FRONTING_PORT` | `443` | `domain-fronting-port` |
| `-mtproto-fronting-host` | `MTPROTO_FRONTING_HOST` | _(secret host)_ | `[domain-fronting] host` |
| `-mtproto-prefer-ip` | `MTPROTO_PREFER_IP` | `prefer-ipv6` | `prefer-ip` |
| `-mtproto-allow-fallback-dc` | `MTPROTO_ALLOW_FALLBACK_DC` | `false` | `allow-fallback-on-unknown-dc` |
| `-mtproto-autoupdate` | `MTPROTO_AUTOUPDATE` | `false` | `autoupdate` |
| `-mtproto-idle-timeout` | `MTPROTO_IDLE_TIMEOUT` | `5m` | `idle-timeout` |
| `-mtproto-handshake-timeout` | `MTPROTO_HANDSHAKE_TIMEOUT` | `10s` | `handshake-timeout` |
| `-mtproto-tolerate-skew` | `MTPROTO_TOLERATE_SKEW` | `3s` | `tolerate-time-skewness` |
| `-mtproto-doppelganger-drs` | `MTPROTO_DOPPELGANGER_DRS` | `false` | `doppelganger` DRS |
| `-gen-secret` | — | | generate a secret and exit |
| `-gen-host` | `MTPROTO_SECRET_HOST` | `www.google.com` | fronting host in the secret |

`MTPROTO_FRONTING_HOST` changes only where mtg *dials* for domain fronting
(useful when DNS for the secret's host is blocked or loops back to the server);
the secret's hostname is still used for SNI. `-gen-host` is only used when
creating a new secret.

## Install as a System Service

```bash
sudo ./cmd.sh install
sudo ./cmd.sh install 0.0.0.0:1080 myuser 'strong-password'
sudo ./cmd.sh install 0.0.0.0:1080 myuser 'strong-password' ee<secret>
sudo ./cmd.sh install 0.0.0.0:1080 myuser 'strong-password' ee<secret> 0.0.0.0:8443
```

Creates `/usr/local/bin/proxy-server`, `/etc/proxy-server/proxy.env` and a
hardened `proxy-server.service` (auto-start, restart on failure,
`CAP_NET_BIND_SERVICE` so it can bind 443/80).

```bash
journalctl -u proxy-server -f    # logs (add PROXY_VERBOSE=true for mtg internals)
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

## Proxy options

| Flag | Env / `.env` | Default |
|------|---------------|---------|
| `-addr` | `PROXY_ADDR` / `PROXY_PORT` / `PORT` | `0.0.0.0:1080` |
| `-username` | `PROXY_USERNAME` | _(empty = no auth)_ |
| `-password` | `PROXY_PASSWORD` | |
| `-timeout` | `PROXY_TIMEOUT` | `30s` |
| `-v` | `PROXY_VERBOSE` | verbose logging |

## Features

- **One port, three protocols** — first bytes select SOCKS5 (`0x05`),
  HTTP (method letters), or MTProto fake TLS (`0x16`).
- SOCKS5 `CONNECT` + `UDP ASSOCIATE` (RFC 1928), user/pass auth (RFC 1929).
- HTTP `CONNECT` tunnels (HTTPS) + absolute-URI forwarding (plain HTTP).
- MTProto via [mtg](https://github.com/9seconds/mtg): fake TLS, domain
  fronting for probes, shared anti-replay cache, direct DC connections,
  IPv4/IPv6 preference, graceful shutdown.
- Constant-time credential comparison, configurable dial timeout.

## Uninstall

```bash
sudo ./uninstall.sh
```

## Files

```
cmd.sh              build, install (systemd) and run in one entry point
main.go             CLI flags + unified listener (SOCKS5/HTTP/MTProto)
socks5.go           SOCKS5 server (CONNECT / UDP ASSOCIATE)
httpproxy.go        HTTP forward proxy (CONNECT / GET forwarding)
mtproto.go          MTProto (Telegram) via mtg mtglib: secret matching,
                    domain fronting, concurrency, logging, events
config.go           Auth, timeouts, env helpers, MTProto config
env.go              .env loading + address normalization
uninstall.sh        remove service
test.sh             curl smoke-tests
mtproto_test.go     secret parsing, fake-TLS matching, links, validation
```
