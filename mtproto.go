package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/events"
	"github.com/9seconds/mtg/v2/ipblocklist"
	"github.com/9seconds/mtg/v2/logger"
	"github.com/9seconds/mtg/v2/mtglib"
	network "github.com/9seconds/mtg/v2/network/v2"
)

// Telegram MTProto support is provided by github.com/9seconds/mtg (mtglib),
// a mature, fast obfuscated2/fake-TLS implementation. Each configured secret
// gets its own mtglib.Proxy. The shared SOCKS5/HTTP port sniffs the first
// bytes and routes MTProto-looking connections to the right proxy;
// MTPROTO_ADDR can additionally expose a dedicated MTProto-only listener.
//
// mtg only accepts fake-TLS ("ee") secrets: the secret carries the domain
// fronting hostname used for SNI and fallback.

const (
	mtpHandshakeLen = 64
	mtpTLSHandshake = 0x16
)

// MTProtoConfig holds the Telegram side of the server.
type MTProtoConfig struct {
	Secrets []mtglib.Secret
	Timeout time.Duration
	Verbose bool

	// proxies[i] serves Secrets[i]. Built by newMTProtoManager.
	proxies []*mtglib.Proxy
}

func (c *Config) mtprotoEnabled() bool {
	return c.MTProto != nil && len(c.MTProto.Secrets) > 0
}

// newMTProtoManager builds one mtg proxy per secret. The returned cleanup
// shuts them all down.
func newMTProtoManager(mc *MTProtoConfig) (func(), error) {
	ntw := network.New(
		net.DefaultResolver,
		"",
		mc.Timeout,
		0,
		0,
		net.KeepAliveConfig{
			Enable:   true,
			Idle:     30 * time.Second,
			Interval: 10 * time.Second,
			Count:    3,
		},
	)

	mc.proxies = make([]*mtglib.Proxy, len(mc.Secrets))
	for i := range mc.Secrets {
		p, err := mtglib.NewProxy(mtglib.ProxyOpts{
			Logger:          logger.NewNoopLogger(),
			Network:         ntw,
			AntiReplayCache: antireplay.NewStableBloomFilter(0, 0),
			IPBlocklist:     ipblocklist.NewNoop(),
			IPAllowlist:     ipblocklist.NewNoop(),
			EventStream:     events.NewNoopStream(),

			Secret:               mc.Secrets[i],
			Concurrency:          mtglib.DefaultConcurrency,
			DomainFrontingPort:   mtglib.DefaultDomainFrontingPort,
			PreferIP:             mtglib.DefaultPreferIP,
			TolerateTimeSkewness: mtglib.DefaultTolerateTimeSkewness,
			IdleTimeout:          mtglib.DefaultIdleTimeout,
			HandshakeTimeout:     mtglib.DefaultHandshakeTimeout,
		})
		if err != nil {
			for _, old := range mc.proxies[:i] {
				old.Shutdown()
			}
			return nil, fmt.Errorf("mtproto secret %d: %w", i+1, err)
		}
		mc.proxies[i] = p
	}

	return func() {
		for _, p := range mc.proxies {
			p.Shutdown()
		}
	}, nil
}

// mtprotoConn adapts a buffered net.Conn to essentials.Conn (CloseRead /
// CloseWrite), which mtg requires.
type mtprotoConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *mtprotoConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *mtprotoConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return c.Conn.Close()
}

func (c *mtprotoConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

var _ essentials.Conn = (*mtprotoConn)(nil)

// serveMTProto handles one connection on the MTProto-only listener. The first
// secret's proxy is used; mtg itself validates the handshake.
func serveMTProto(conn net.Conn, mc *MTProtoConfig) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(mc.Timeout))
	br := bufio.NewReaderSize(conn, 8*1024)
	mc.proxies[0].ServeConn(&mtprotoConn{Conn: conn, r: br})
}

// dispatchMTProto routes a connection on the shared port to the mtg proxy
// whose secret authenticates it. It returns handled=true when the connection
// was consumed (either served or rejected by mtg).
func dispatchMTProto(conn *bufferedConn, mc *MTProtoConfig) bool {
	br := conn.R
	first, err := br.Peek(1)
	if err != nil {
		return false
	}

	if first[0] == mtpTLSHandshake {
		idx := matchMTProtoFakeTLS(br, mc.Secrets)
		if idx < 0 {
			return false
		}
		mc.proxies[idx].ServeConn(&mtprotoConn{Conn: conn.Conn, r: br})
		return true
	}

	idx := matchMTProtoObfuscated2(br, mc.Secrets)
	if idx < 0 {
		return false
	}
	mc.proxies[idx].ServeConn(&mtprotoConn{Conn: conn.Conn, r: br})
	return true
}

// matchMTProtoObfuscated2 validates the 64-byte obfuscated2 header against
// each secret (SHA256(key||secret) + tag check) without consuming the peeked
// bytes. Returns the matching secret index or -1.
func matchMTProtoObfuscated2(br *bufio.Reader, secrets []mtglib.Secret) int {
	frame, err := br.Peek(mtpHandshakeLen)
	if err != nil {
		return -1
	}

	for i := range secrets {
		key := frame[8:40]
		var buf [48]byte
		copy(buf[:32], key)
		copy(buf[32:], secrets[i].Key[:])
		decKey := sha256.Sum256(buf[:])

		block, err := aes.NewCipher(decKey[:])
		if err != nil {
			continue
		}
		dec := cipher.NewCTR(block, frame[40:56])

		var scratch [mtpHandshakeLen]byte
		copy(scratch[:], frame[:])
		dec.XORKeyStream(scratch[:], scratch[:])

		tag := binary.LittleEndian.Uint32(scratch[56:60])
		if tag == 0xdddddddd || tag == 0xeeeeeeee || tag == 0xefefefef {
			return i
		}
	}
	return -1
}

// matchMTProtoFakeTLS checks the ClientHello HMAC against each secret without
// consuming the buffered bytes. Returns the matching secret index or -1.
func matchMTProtoFakeTLS(br *bufio.Reader, secrets []mtglib.Secret) int {
	hdr, err := br.Peek(5)
	if err != nil || hdr[0] != mtpTLSHandshake {
		return -1
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 4 || recLen > 16384+2048 {
		return -1
	}
	raw, err := br.Peek(5 + recLen)
	if err != nil {
		return -1
	}

	// ClientHello: record(5) + handshake(4) + version(2) + random(32) ...
	const randomOffset = 5 + 4 + 2
	if len(raw) < randomOffset+32 {
		return -1
	}
	clientRandom := raw[randomOffset : randomOffset+32]

	// HMAC over the hello with the random field zeroed.
	var zeroed []byte
	zeroed = append(zeroed, raw[:randomOffset]...)
	zeroed = append(zeroed, make([]byte, 32)...)
	zeroed = append(zeroed, raw[randomOffset+32:]...)

	for i := range secrets {
		mac := hmac.New(sha256.New, secrets[i].Key[:])
		mac.Write(zeroed)
		var x [32]byte
		for j := range x {
			x[j] = mac.Sum(nil)[j] ^ clientRandom[j]
		}
		if subtle.ConstantTimeCompare(x[:28], make([]byte, 28)) == 1 {
			return i
		}
	}
	return -1
}

// parseMTProtoSecrets parses a comma-separated list of fake-TLS secrets
// (hex or base64, as produced by `mtg generate-secret` / Telegram).
func parseMTProtoSecrets(raw string) ([]mtglib.Secret, error) {
	var out []mtglib.Secret
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		sec, err := mtglib.ParseSecret(item)
		if err != nil {
			return nil, fmt.Errorf("secret %q: %w", item, err)
		}
		out = append(out, sec)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no MTProto secret configured")
	}
	return out, nil
}

// mtprotoLink renders a tg:// link for a secret.
func mtprotoLink(sec mtglib.Secret, addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "SERVER"
	}
	return fmt.Sprintf("tg://proxy?server=%s&port=%s&secret=%s", host, port, sec.Hex())
}

// isHTTPPrefix reports whether the buffered bytes look like an HTTP request
// method. MTProto headers are random and Telegram clients avoid these values.
func isHTTPPrefix(br *bufio.Reader) bool {
	b, err := br.Peek(4)
	if err != nil {
		return false
	}
	switch string(b) {
	case "GET ", "POST", "CONN", "HEAD", "PUT ", "DELE", "OPTI", "PATC", "TRAC":
		return true
	}
	return false
}

// isSOCKS5Greeting distinguishes a SOCKS5 greeting from a random MTProto
// header that happens to start with 0x05.
func isSOCKS5Greeting(br *bufio.Reader) bool {
	h, err := br.Peek(2)
	if err != nil || h[0] != 0x05 {
		return false
	}
	n := int(h[1])
	if n == 0 {
		return true
	}
	if n > 8 {
		return false
	}
	b, err := br.Peek(2 + n)
	if err != nil {
		return false
	}
	for _, m := range b[2:] {
		if m == 0x00 || m == 0x02 {
			return true
		}
	}
	return false
}
