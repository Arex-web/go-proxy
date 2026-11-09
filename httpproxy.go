package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTP forward proxy: handles CONNECT tunnels + absolute-URI GET/POST forwarding.

func handleHTTP(conn *bufferedConn, cfg *Config) {
	// Clear sniff deadline; use no deadline for HTTP read (tunnel is long-lived)
	_ = conn.SetDeadline(time.Time{})

	// conn.R already holds peeked bytes; use it directly (no double-buffer)
	br := conn.R
	req, err := http.ReadRequest(br)
	if err != nil {
		if cfg.Verbose {
			log.Printf("[http] bad request from %s: %v", conn.RemoteAddr(), err)
		}
		return
	}

	// Auth check
	if !cfg.checkHTTPAuth(req.Header.Get("Proxy-Authorization")) {
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")
		if cfg.Verbose {
			log.Printf("[http] auth FAILED %s %s from %s", req.Method, req.URL, conn.RemoteAddr())
		}
		return
	}

	if req.Method == http.MethodConnect {
		handleConnect(conn, req, cfg)
		return
	}

	// Regular absolute-URI proxying: GET http://example.com/path HTTP/1.1
	if req.URL == nil || !req.URL.IsAbs() {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}
	doHTTPForward(conn, req, cfg)
}

func handleConnect(client *bufferedConn, req *http.Request, cfg *Config) {
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	if !strings.Contains(target, ":") {
		target = net.JoinHostPort(target, "443")
	}

	d := net.Dialer{Timeout: cfg.Timeout}
	remote, err := d.Dial("tcp", target)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		if cfg.Verbose {
			log.Printf("[http CONNECT] -> %s failed: %v", target, err)
		}
		return
	}
	defer remote.Close()

	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if cfg.Verbose {
		log.Printf("[http CONNECT] %s -> %s", client.RemoteAddr(), target)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(remote, client); if tc, ok := remote.(*net.TCPConn); ok { _ = tc.CloseWrite() } }()
	go func() { defer wg.Done(); _, _ = io.Copy(client, remote); if tc, ok := client.Conn.(*net.TCPConn); ok { _ = tc.CloseWrite() } }()
	wg.Wait()
}

// doHTTPForward fetches req.URL (absolute) via http.Client and streams response back.
func doHTTPForward(client *bufferedConn, req *http.Request, cfg *Config) {
	// Build outbound request to the absolute URL
	outReq, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), req.Body)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		if cfg.Verbose {
			log.Printf("[http] NewRequest failed: %v", err)
		}
		return
	}
	// Copy headers except hop-by-hop / proxy headers
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		if lk == "proxy-authorization" || lk == "proxy-connection" || lk == "proxy-authenticate" ||
			lk == "connection" || lk == "keep-alive" || lk == "te" || lk == "trailer" {
			continue
		}
		for _, v := range vs {
			outReq.Header.Add(k, v)
		}
	}
	outReq.ContentLength = req.ContentLength
	// Preserve original Host / headers
	if req.Host != "" {
		outReq.Host = req.Host
	}

	tr := &http.Transport{
		DialContext: (&net.Dialer{Timeout: cfg.Timeout}).DialContext,
		DisableKeepAlives: true,
	}
	httpClient := &http.Client{Transport: tr, Timeout: 0}

	resp, err := httpClient.Do(outReq)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		if cfg.Verbose {
			log.Printf("[http] forward %s %s failed: %v", req.Method, req.URL, err)
		}
		return
	}
	defer resp.Body.Close()

	if cfg.Verbose {
		log.Printf("[http] %s %s -> %s", req.Method, req.URL, resp.Status)
	}

	// Write status line + headers + body
	// resp.Write handles framing correctly
	_ = resp.Write(client)
}
