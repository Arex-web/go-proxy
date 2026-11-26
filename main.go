package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/9seconds/mtg/v2/mtglib"
)

func main() {
	loadEnv()

	var (
		addr     = flag.String("addr", envOr("PROXY_ADDR", "0.0.0.0:1080"), "Listen address (from .env: PROXY_ADDR / PROXY_PORT / PORT)")
		username = flag.String("username", envOr("PROXY_USERNAME", ""), "Proxy username (empty = no auth)")
		password = flag.String("password", envOr("PROXY_PASSWORD", ""), "Proxy password")
		timeout  = flag.Duration("timeout", envDuration("PROXY_TIMEOUT", 30*time.Second), "Dial / sniff timeout")
		verbose  = flag.Bool("v", envBool("PROXY_VERBOSE", false), "Verbose logging (includes mtg internals and events)")

		mtpSecret = flag.String("mtproto-secret", envOr("MTPROTO_SECRET", ""),
			"MTProto fake-TLS secret(s), comma separated (hex or base64; see -gen-secret)")
		mtpAddr = flag.String("mtproto-addr", envOr("MTPROTO_ADDR", ""),
			"Extra MTProto-only listen address (main port always accepts MTProto)")
		genSecret = flag.Bool("gen-secret", false, "Generate a random fake-TLS secret and exit")
		genHost   = flag.String("gen-host", envOr("MTPROTO_SECRET_HOST", "www.google.com"),
			"Domain fronting host baked into -gen-secret")

		mtpConcurrency = flag.Uint("mtproto-concurrency", envUint("MTPROTO_CONCURRENCY", mtglib.DefaultConcurrency),
			"Max simultaneous MTProto streams per secret (mtg: concurrency)")
		mtpFrontingHost = flag.String("mtproto-fronting-host", envOr("MTPROTO_FRONTING_HOST", ""),
			"Dial target for the fronting domain (mtg: [domain-fronting] host); SNI stays the secret host")
		mtpFrontingPort = flag.Uint("mtproto-fronting-port", envUint("MTPROTO_FRONTING_PORT", mtglib.DefaultDomainFrontingPort),
			"Port used to reach the fronting domain (mtg: domain-fronting-port)")
		mtpPreferIP = flag.String("mtproto-prefer-ip", envOr("MTPROTO_PREFER_IP", mtglib.DefaultPreferIP),
			"IP preference: prefer-ipv4, prefer-ipv6, only-ipv4, only-ipv6")
		mtpAllowFallback = flag.Bool("mtproto-allow-fallback-dc", envBool("MTPROTO_ALLOW_FALLBACK_DC", false),
			"Use any DC when a client asks for an unknown one (mtg: allow-fallback-on-unknown-dc)")
		mtpAutoUpdate = flag.Bool("mtproto-autoupdate", envBool("MTPROTO_AUTOUPDATE", false),
			"Refresh the Telegram DC list in the background (mtg: autoupdate)")
		mtpIdleTimeout = flag.Duration("mtproto-idle-timeout", envDuration("MTPROTO_IDLE_TIMEOUT", mtglib.DefaultIdleTimeout),
			"Close idle MTProto relays after this long (mtg: idle-timeout)")
		mtpHandshakeTimeout = flag.Duration("mtproto-handshake-timeout", envDuration("MTPROTO_HANDSHAKE_TIMEOUT", mtglib.DefaultHandshakeTimeout),
			"Time allowed for the full MTProto handshake (mtg: handshake-timeout)")
		mtpTolerateSkew = flag.Duration("mtproto-tolerate-skew", envDuration("MTPROTO_TOLERATE_SKEW", mtglib.DefaultTolerateTimeSkewness),
			"Accepted fake-TLS timestamp skew (mtg: tolerate-time-skewness)")
		mtpDRS = flag.Bool("mtproto-doppelganger-drs", envBool("MTPROTO_DOPPELGANGER_DRS", false),
			"Use TLS dynamic record sizing for the doppelganger (mtg: doppelganger-drs)")
	)
	flag.Parse()

	if *genSecret {
		printSecret(*genHost, normalizeAddr(*addr))
		return
	}

	cfg := &Config{
		Username: *username,
		Password: *password,
		Timeout:  *timeout,
		Verbose:  *verbose,
	}

	if *mtpSecret != "" {
		secrets, err := parseMTProtoSecrets(*mtpSecret)
		if err != nil {
			log.Fatalf("mtproto secret: %v", err)
		}
		cfg.MTProto = &MTProtoConfig{
			Secrets:                  secrets,
			Concurrency:              *mtpConcurrency,
			DomainFrontingHost:       *mtpFrontingHost,
			DomainFrontingPort:       *mtpFrontingPort,
			PreferIP:                 *mtpPreferIP,
			AllowFallbackOnUnknownDC: *mtpAllowFallback,
			AutoUpdate:               *mtpAutoUpdate,
			IdleTimeout:              *mtpIdleTimeout,
			HandshakeTimeout:         *mtpHandshakeTimeout,
			TolerateTimeSkewness:     *mtpTolerateSkew,
			DoppelGangerDRS:          *mtpDRS,
			DialTimeout:              *timeout,
			Verbose:                  *verbose,
		}
	}

	if err := run(cfg, normalizeAddr(*addr), *mtpAddr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func run(cfg *Config, addr, extraMTProtoAddr string) error {
	ln, err := listen(addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer ln.Close()

	log.Printf("proxy-server listening on %s (SOCKS5+HTTP+MTProto unified)", addr)
	logAuth(cfg, addr)

	var extraLn net.Listener
	if cfg.mtprotoEnabled() && extraMTProtoAddr != "" {
		if mtpAddr := normalizeAddr(extraMTProtoAddr); mtpAddr != addr {
			extraLn, err = listen(mtpAddr)
			if err != nil {
				return fmt.Errorf("mtproto listen %s: %w", mtpAddr, err)
			}
			defer extraLn.Close()
		}
	}

	if cfg.mtprotoEnabled() {
		shutdown, err := newMTProtoManager(cfg.MTProto)
		if err != nil {
			return err
		}
		defer shutdown()

		logMTProtoConfig(cfg.MTProto, addr)

		if extraLn != nil {
			log.Printf("mtproto: extra listener on %s", extraLn.Addr())
			go func() {
				if err := acceptLoop(extraLn, func(c net.Conn) { serveMTProto(c, cfg.MTProto) }); err != nil {
					log.Printf("mtproto listener stopped: %v", err)
				}
			}()
		}
	} else {
		log.Printf("mtproto: disabled (set MTPROTO_SECRET=ee... ; generate one with -gen-secret)")
	}

	// mtg shuts its relays down gracefully; do the same for the listeners so
	// systemd restarts start from a clean state.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	acceptErr := make(chan error, 1)
	go func() { acceptErr <- acceptLoop(ln, func(c net.Conn) { handleConn(c, cfg) }) }()

	select {
	case err := <-acceptErr:
		return err
	case <-ctx.Done():
		log.Printf("shutdown signal received, stopping")
		_ = ln.Close()
		if extraLn != nil {
			_ = extraLn.Close()
		}
		return nil
	}
}

func logAuth(cfg *Config, addr string) {
	creds := ""
	if cfg.authEnabled() {
		creds = cfg.Username + ":PASSWORD@"
		log.Printf("auth: ENABLED (user=%s)", cfg.Username)
	} else {
		log.Printf("auth: DISABLED (public proxy - set PROXY_USERNAME/PROXY_PASSWORD)")
	}
	log.Printf("Test SOCKS5:  curl -x socks5h://%s%s https://example.com", creds, addr)
	log.Printf("Test HTTP:    curl -x http://%s%s https://example.com", creds, addr)
}

// printSecret generates a fake-TLS secret, which is the only secret kind mtg
// (and therefore this server) accepts.
func printSecret(host, addr string) {
	secret := mtglib.GenerateSecret(host)

	fmt.Printf("secret (hex):     %s\n", secret.Hex())
	fmt.Printf("secret (base64):  %s\n", secret.Base64())
	fmt.Printf("fronting host:    %s\n", secret.Host)
	fmt.Println()
	fmt.Printf("Add to .env:\n  MTPROTO_SECRET=%s\n\n", secret.Hex())
	fmt.Println(mtprotoLink(secret, addr))
	fmt.Println(mtprotoWebLink(secret, addr))
}

func acceptLoop(ln net.Listener, serve func(net.Conn)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if isClosedError(err) {
				return nil
			}
			return err
		}
		go serve(conn)
	}
}

// handleConn sniffs the first bytes to decide SOCKS5 vs HTTP vs MTProto on
// the same port. SOCKS5 starts with 0x05; HTTP with an ASCII method; MTProto
// fake TLS with 0x16.
func handleConn(conn net.Conn, cfg *Config) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))

	br := bufio.NewReaderSize(conn, mtpSniffBufferSize)
	first, err := br.Peek(1)
	if err != nil {
		return
	}

	wrapped := &bufferedConn{Conn: conn, R: br}

	if cfg.mtprotoEnabled() && first[0] == mtpTLSHandshake {
		// Fake TLS from a Telegram client, or any HTTPS client hitting this
		// port: mtg serves it or domain-fronts it.
		dispatchMTProto(wrapped, cfg.MTProto)
		return
	}

	if first[0] == socksVersion {
		if isSOCKS5Greeting(br) {
			handleSOCKS5(wrapped, cfg)
			return
		}
	} else if isHTTPPrefix(br) {
		handleHTTP(wrapped, cfg)
		return
	}

	if cfg.Verbose {
		log.Printf("unknown protocol from %s (first byte %#x), closing", conn.RemoteAddr(), first[0])
	}
}
