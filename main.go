package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	loadEnv()

	var (
		addr     string
		username string
		password string
		timeout  time.Duration
		verbose  bool
	)

	flag.StringVar(&addr, "addr", envOr("PROXY_ADDR", "0.0.0.0:1080"), "Listen address (from .env: PROXY_ADDR / PROXY_PORT / PORT)")
	flag.StringVar(&username, "username", envOr("PROXY_USERNAME", ""), "Proxy username (empty = no auth)")
	flag.StringVar(&password, "password", envOr("PROXY_PASSWORD", ""), "Proxy password")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "Dial / IO timeout")
	flag.BoolVar(&verbose, "v", false, "Verbose logging")
	flag.Parse()

	// Accept bare ports on the flag too: -addr 26398 -> 0.0.0.0:26398
	addr = normalizeAddr(addr)

	if err := run(addr, username, password, timeout, verbose); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func run(addr, username, password string, timeout time.Duration, verbose bool) error {
	cfg := &Config{
		Username: username,
		Password: password,
		Timeout:  timeout,
		Verbose:  verbose,
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

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleConn(conn, cfg)
	}
}

// handleConn sniffs the first byte to decide SOCKS5 vs HTTP on the same port.
// SOCKS5 always starts with 0x05. HTTP starts with ASCII method letters (G,P,D,C,O...).
func handleConn(conn net.Conn, cfg *Config) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))

	br := bufio.NewReader(conn)
	// Peek 1 byte without consuming
	b, err := br.Peek(1)
	if err != nil {
		return
	}

	// Wrap conn to use the buffered reader
	wrapped := &bufferedConn{Conn: conn, R: br}

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
