package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/9seconds/mtg/v2/mtglib"
)

func main() {
	loadEnv()

	var (
		addr      string
		username  string
		password  string
		timeout   time.Duration
		verbose   bool
		mtpSecret string
		mtpAddr   string
		genSecret bool
		genHost   string
	)

	flag.StringVar(&addr, "addr", envOr("PROXY_ADDR", "0.0.0.0:1080"), "Listen address (from .env: PROXY_ADDR / PROXY_PORT / PORT)")
	flag.StringVar(&username, "username", envOr("PROXY_USERNAME", ""), "Proxy username (empty = no auth)")
	flag.StringVar(&password, "password", envOr("PROXY_PASSWORD", ""), "Proxy password")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "Dial / IO timeout")
	flag.BoolVar(&verbose, "v", false, "Verbose logging")
	flag.StringVar(&mtpSecret, "mtproto-secret", envOr("MTPROTO_SECRET", ""), "MTProto fake-TLS secret(s), comma separated (hex or base64; see -gen-secret)")
	flag.StringVar(&mtpAddr, "mtproto-addr", envOr("MTPROTO_ADDR", ""), "Extra MTProto-only listen address (main port always accepts MTProto)")
	flag.BoolVar(&genSecret, "gen-secret", false, "Generate a random MTProto secret and exit")
	flag.StringVar(&genHost, "gen-host", envOr("MTPROTO_FRONTING_HOST", "www.google.com"), "Domain fronting host used with -gen-secret")
	flag.Parse()

	if genSecret {
		sec := mtglib.GenerateSecret(genHost)
		fmt.Println(sec.Hex())
		fmt.Printf("Add to .env:  MTPROTO_SECRET=%s\n", sec.Hex())
		return
	}

	// Accept bare ports on the flag too: -addr 26398 -> 0.0.0.0:26398
	addr = normalizeAddr(addr)

	if err := run(addr, username, password, timeout, verbose, mtpSecret, mtpAddr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func run(addr, username, password string, timeout time.Duration, verbose bool, mtpSecret, mtpAddr string) error {
	cfg := &Config{
		Username: username,
		Password: password,
		Timeout:  timeout,
		Verbose:  verbose,
	}

	if mtpSecret != "" {
		secrets, err := parseMTProtoSecrets(mtpSecret)
		if err != nil {
			return fmt.Errorf("mtproto secret: %w", err)
		}
		cfg.MTProto = &MTProtoConfig{
			Secrets: secrets,
			Timeout: timeout,
			Verbose: verbose,
		}
	}

	ln, err := listen(addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer ln.Close()

	log.Printf("proxy-server listening on %s (SOCKS5+HTTP unified)", addr)
	if username != "" {
		log.Printf("auth: ENABLED (user=%s)", username)
	} else {
		log.Printf("auth: DISABLED (public proxy - set -username/-password or PROXY_USERNAME/PROXY_PASSWORD)")
	}
	log.Printf("Test SOCKS5:  curl -x socks5h://%s@127.0.0.1:1080 https://example.com", username)
	log.Printf("Test HTTP:   curl -x http://%s@127.0.0.1:1080 https://example.com", username)

	if cfg.mtprotoEnabled() {
		shutdown, err := newMTProtoManager(cfg.MTProto)
		if err != nil {
			return err
		}
		defer shutdown()

		log.Printf("mtproto: ENABLED on %s (shared with SOCKS5/HTTP)", addr)
		for i := range cfg.MTProto.Secrets {
			sec := &cfg.MTProto.Secrets[i]
			log.Printf("mtproto: secret %s (fronting %s)", sec.Hex(), sec.Host)
			if link := mtprotoLink(*sec, addr); link != "" {
				log.Printf("mtproto: %s", link)
			}
		}

		if mtpAddr != "" {
			ma := normalizeAddr(mtpAddr)
			if ma != addr {
				ln2, err := listen(ma)
				if err != nil {
					return fmt.Errorf("mtproto listen %s: %w", ma, err)
				}
				defer ln2.Close()
				log.Printf("mtproto: extra listener on %s", ma)
				go func() {
					if err := acceptLoop(ln2, func(c net.Conn) { serveMTProto(c, cfg.MTProto) }); err != nil {
						log.Printf("mtproto listener stopped: %v", err)
					}
				}()
			}
		}
	} else {
		log.Printf("mtproto: disabled (set MTPROTO_SECRET=ee... ; generate one with -gen-secret)")
	}

	return acceptLoop(ln, func(c net.Conn) { handleConn(c, cfg) })
}

func acceptLoop(ln net.Listener, serve func(net.Conn)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}
		go serve(conn)
	}
}

// handleConn sniffs the first bytes to decide SOCKS5 vs HTTP vs MTProto on
// the same port. SOCKS5 starts with 0x05; HTTP with an ASCII method;
// MTProto with 0x16 (fake TLS) or a random header.
func handleConn(conn net.Conn, cfg *Config) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))

	br := bufio.NewReaderSize(conn, 8*1024)
	b, err := br.Peek(1)
	if err != nil {
		return
	}

	wrapped := &bufferedConn{Conn: conn, R: br}

	if cfg.mtprotoEnabled() {
		switch {
		case b[0] == mtpTLSHandshake:
			// Fake TLS, or a real HTTPS client hitting the wrong port.
			if dispatchMTProto(wrapped, cfg.MTProto) {
				return
			}
		case b[0] == 0x05:
			if !isSOCKS5Greeting(br) {
				if dispatchMTProto(wrapped, cfg.MTProto) {
					return
				}
			}
		default:
			if !isHTTPPrefix(br) {
				if dispatchMTProto(wrapped, cfg.MTProto) {
					return
				}
			}
		}
	}

	if b[0] == 0x05 {
		handleSOCKS5(wrapped, cfg)
	} else {
		handleHTTP(wrapped, cfg)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
