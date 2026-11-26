package main

// Telegram MTProto support is provided by github.com/9seconds/mtg (mtglib),
// the engine behind the mtg proxy server. Each configured secret gets its own
// mtglib.Proxy; the shared SOCKS5/HTTP port sniffs the first byte and routes
// fake-TLS connections to the proxy whose secret authenticates them.
//
// What mtg implements - and therefore what this server implements too:
//
//   - fake-TLS ("ee") secrets only. mtg dropped plain obfuscated2 and "dd"
//     secrets, so every secret generated here is an ee... fake-TLS secret.
//   - domain fronting: a TLS client that does not authenticate with any secret
//     is forwarded to the fronting host instead of being rejected, so probing
//     the port returns a normal HTTPS site (probe resistance).
//   - one shared anti-replay cache, direct DC connections, IPv4/IPv6
//     preference and the module's own handshake/idle timeouts.
//
// MTProtoConfig mirrors [mtglib.ProxyOpts] one to one, so mtg's documentation
// applies directly to the flags exposed by this server.

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/events"
	"github.com/9seconds/mtg/v2/ipblocklist"
	"github.com/9seconds/mtg/v2/logger"
	"github.com/9seconds/mtg/v2/mtglib"
	network "github.com/9seconds/mtg/v2/network/v2"
)

const (
	// mtpTLSHandshake is the TLS handshake record type a fake-TLS client
	// starts with (and so does any real HTTPS client).
	mtpTLSHandshake = 0x16

	// mtpSniffBufferSize is the peek buffer used to look at a ClientHello
	// before handing the connection to mtg. Telegram's ClientHello is a few
	// hundred bytes; anything bigger is handed to mtg unsniffed and ends up
	// domain-fronted.
	mtpSniffBufferSize = 8 * 1024

	// mtpMaxTLSRecord is the largest TLS record we are willing to buffer while
	// matching a secret (16 KiB payload + slack, as in crypto/tls).
	mtpMaxTLSRecord = 16384 + 2048
)

// MTProtoConfig is the Telegram side of the server.
type MTProtoConfig struct {
	// Secrets are the fake-TLS secrets clients authenticate with.
	Secrets []mtglib.Secret

	// The fields below mirror mtglib.ProxyOpts. Zero values mean "use mtg's
	// default", exactly like in mtg's own configuration file.
	Concurrency              uint
	DomainFrontingHost       string
	DomainFrontingPort       uint
	PreferIP                 string
	AllowFallbackOnUnknownDC bool
	AutoUpdate               bool
	IdleTimeout              time.Duration
	HandshakeTimeout         time.Duration
	TolerateTimeSkewness     time.Duration
	DoppelGangerDRS          bool

	// DialTimeout is used for connections mtg opens itself (Telegram DCs and
	// the fronting host).
	DialTimeout time.Duration

	// Verbose enables mtg's own logging and event stream.
	Verbose bool

	// proxies[i] serves Secrets[i], slots[i] limits its concurrent streams.
	proxies    []*mtglib.Proxy
	slots      []chan struct{}
	stopEvents func()
	closeOnce  sync.Once
}

func (c *Config) mtprotoEnabled() bool {
	return c.MTProto != nil && len(c.MTProto.Secrets) > 0
}

var mtpPreferIPValues = []string{"prefer-ipv4", "prefer-ipv6", "only-ipv4", "only-ipv6"}

func (mc *MTProtoConfig) validate() error {
	if len(mc.Secrets) == 0 {
		return fmt.Errorf("no MTProto secret configured")
	}
	if preferIP := mc.effectivePreferIP(); !slices.Contains(mtpPreferIPValues, preferIP) {
		return fmt.Errorf("invalid prefer-ip %q (want one of %s)",
			preferIP, strings.Join(mtpPreferIPValues, ", "))
	}
	if mc.DomainFrontingPort > 65535 {
		return fmt.Errorf("invalid fronting port %d", mc.DomainFrontingPort)
	}
	if mc.Concurrency > 1<<16 {
		return fmt.Errorf("invalid concurrency %d (max 65536)", mc.Concurrency)
	}
	return nil
}

// The effective* helpers return the value mtg would actually use, so logs show
// the real configuration rather than a zero that means "default".

func (mc *MTProtoConfig) effectiveConcurrency() uint {
	if mc.Concurrency == 0 {
		return mtglib.DefaultConcurrency
	}
	return mc.Concurrency
}

func (mc *MTProtoConfig) effectiveDomainFrontingPort() uint {
	if mc.DomainFrontingPort == 0 {
		return mtglib.DefaultDomainFrontingPort
	}
	return mc.DomainFrontingPort
}

func (mc *MTProtoConfig) effectivePreferIP() string {
	if mc.PreferIP == "" {
		return mtglib.DefaultPreferIP
	}
	return mc.PreferIP
}

func (mc *MTProtoConfig) effectiveIdleTimeout() time.Duration {
	if mc.IdleTimeout == 0 {
		return mtglib.DefaultIdleTimeout
	}
	return mc.IdleTimeout
}

func (mc *MTProtoConfig) effectiveHandshakeTimeout() time.Duration {
	if mc.HandshakeTimeout == 0 {
		return mtglib.DefaultHandshakeTimeout
	}
	return mc.HandshakeTimeout
}

func (mc *MTProtoConfig) effectiveTolerateTimeSkewness() time.Duration {
	if mc.TolerateTimeSkewness == 0 {
		return mtglib.DefaultTolerateTimeSkewness
	}
	return mc.TolerateTimeSkewness
}

func (mc *MTProtoConfig) dialTimeout() time.Duration {
	if mc.DialTimeout == 0 {
		return 30 * time.Second
	}
	return mc.DialTimeout
}

// newMTProtoManager builds one mtg proxy per secret. The returned cleanup
// shuts them all down.
func newMTProtoManager(mc *MTProtoConfig) (func(), error) {
	if err := mc.validate(); err != nil {
		return nil, err
	}

	ntw := network.New(
		net.DefaultResolver,
		"proxy-server",
		mc.dialTimeout(),
		10*time.Second,
		mc.effectiveIdleTimeout(),
		net.KeepAliveConfig{
			Enable:   true,
			Idle:     30 * time.Second,
			Interval: 10 * time.Second,
			Count:    3,
		},
	)

	// One cache shared by every secret: a ClientHello that was replayed must
	// be rejected regardless of which secret it claims to use. mtg's default
	// size and false-positive rate are selected by passing 0 and -1.
	antiReplay := antireplay.NewStableBloomFilter(0, -1)

	mtgLogger := mc.newLogger()
	eventStream, stopEvents := mc.newEventStream()
	mc.stopEvents = stopEvents

	mc.proxies = make([]*mtglib.Proxy, 0, len(mc.Secrets))
	mc.slots = make([]chan struct{}, 0, len(mc.Secrets))

	for i := range mc.Secrets {
		proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
			Logger:          mtgLogger.Named("secret" + strconv.Itoa(i+1)),
			Network:         ntw,
			AntiReplayCache: antiReplay,
			IPBlocklist:     ipblocklist.NewNoop(),
			IPAllowlist:     ipblocklist.NewNoop(),
			EventStream:     eventStream,

			Secret:                   mc.Secrets[i],
			Concurrency:              mc.effectiveConcurrency(),
			DomainFrontingPort:       mc.effectiveDomainFrontingPort(),
			DomainFrontingHost:       mc.DomainFrontingHost,
			PreferIP:                 mc.effectivePreferIP(),
			AutoUpdate:               mc.AutoUpdate,
			AllowFallbackOnUnknownDC: mc.AllowFallbackOnUnknownDC,
			TolerateTimeSkewness:     mc.effectiveTolerateTimeSkewness(),
			IdleTimeout:              mc.effectiveIdleTimeout(),
			HandshakeTimeout:         mc.effectiveHandshakeTimeout(),
			DoppelGangerDRS:          mc.DoppelGangerDRS,
		})
		if err != nil {
			for _, built := range mc.proxies {
				built.Shutdown()
			}
			stopEvents()
			mc.stopEvents = nil
			return nil, fmt.Errorf("mtproto secret %d: %w", i+1, err)
		}
		mc.proxies = append(mc.proxies, proxy)
		mc.slots = append(mc.slots, make(chan struct{}, mc.effectiveConcurrency()))
	}

	return mc.shutdown, nil
}

func (mc *MTProtoConfig) shutdown() {
	mc.closeOnce.Do(func() {
		for _, proxy := range mc.proxies {
			proxy.Shutdown()
		}
		if mc.stopEvents != nil {
			mc.stopEvents()
			mc.stopEvents = nil
		}
	})
}

// serve hands one sniffed connection to the mtg proxy for proxyIdx, honouring
// the per-secret concurrency limit the same way mtg's listener does.
func (mc *MTProtoConfig) serve(proxyIdx int, conn essentials.Conn) {
	if proxyIdx < 0 || proxyIdx >= len(mc.proxies) {
		return
	}

	slots := mc.slots[proxyIdx]
	select {
	case slots <- struct{}{}:
	default:
		mc.newLogger().Named("concurrency").Warning(
			"limit of " + strconv.Itoa(cap(slots)) + " streams reached, dropping connection")
		return
	}
	defer func() { <-slots }()

	mc.proxies[proxyIdx].ServeConn(conn)
}

// mtprotoConn adapts a buffered net.Conn to essentials.Conn (CloseRead /
// CloseWrite), which mtg requires.
type mtprotoConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *mtprotoConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *mtprotoConn) CloseRead() error {
	if cr, ok := c.Conn.(essentials.CloseableReader); ok {
		return cr.CloseRead()
	}
	return c.Conn.Close()
}

func (c *mtprotoConn) CloseWrite() error {
	if cw, ok := c.Conn.(essentials.CloseableWriter); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

var _ essentials.Conn = (*mtprotoConn)(nil)

// serveMTProto handles one connection on a dedicated MTProto-only listener.
// Every connection goes to mtg; the secret is picked by sniffing when
// possible and defaults to the first proxy otherwise (mtg then falls back to
// domain fronting, which is what a real mtg listener does for unknown
// traffic).
func serveMTProto(conn net.Conn, mc *MTProtoConfig) {
	defer conn.Close()

	br := bufio.NewReaderSize(conn, mtpSniffBufferSize)
	proxyIdx := 0
	if first, err := br.Peek(1); err == nil && first[0] == mtpTLSHandshake {
		if idx := matchMTProtoFakeTLS(br, mc.Secrets); idx >= 0 {
			proxyIdx = idx
		}
	}

	mc.serve(proxyIdx, &mtprotoConn{Conn: conn, r: br})
}

// dispatchMTProto routes a connection on the shared port to the mtg proxy
// whose secret authenticates it. It returns handled=true when the connection
// was consumed.
//
// A TLS handshake that matches no secret is still given to mtg: mtg fails the
// fake-TLS handshake and forwards the bytes to the fronting host, so the port
// keeps looking like the fronting website to probes. Other protocols are left
// for the SOCKS5/HTTP handlers.
func dispatchMTProto(conn *bufferedConn, mc *MTProtoConfig) bool {
	br := conn.R
	first, err := br.Peek(1)
	if err != nil || first[0] != mtpTLSHandshake {
		return false
	}

	proxyIdx := matchMTProtoFakeTLS(br, mc.Secrets)
	if proxyIdx < 0 {
		proxyIdx = 0
		mtgLog(mc).Named("dispatch").Info(
			"TLS client from " + conn.RemoteAddr().String() + " matched no secret, domain fronting")
	}

	mc.serve(proxyIdx, &mtprotoConn{Conn: conn.Conn, r: br})
	return true
}

// matchMTProtoFakeTLS checks the ClientHello HMAC against each secret without
// consuming the buffered bytes. Returns the matching secret index or -1.
//
// The client puts HMAC-SHA256(secret, hello-with-zeroed-random) XOR timestamp
// into the 32-byte ClientHello random; mtg verifies the same value, so
// matching the first 28 bytes is enough to pick the right proxy.
func matchMTProtoFakeTLS(br *bufio.Reader, secrets []mtglib.Secret) int {
	hdr, err := br.Peek(5)
	if err != nil || hdr[0] != mtpTLSHandshake {
		return -1
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 4 || recLen > mtpMaxTLSRecord {
		return -1
	}
	raw, err := br.Peek(5 + recLen)
	if err != nil {
		return -1
	}

	// ClientHello: record(5) + handshake(4) + version(2) + random(32) ...
	const randomOffset = 5 + 4 + 2
	const digestLen = 28 // last 4 bytes of the random are the timestamp
	if len(raw) < randomOffset+32 {
		return -1
	}
	clientRandom := raw[randomOffset : randomOffset+32]

	// HMAC over the hello with the random field zeroed.
	zeroed := make([]byte, 0, len(raw))
	zeroed = append(zeroed, raw[:randomOffset]...)
	zeroed = append(zeroed, make([]byte, 32)...)
	zeroed = append(zeroed, raw[randomOffset+32:]...)

	for i := range secrets {
		mac := hmac.New(sha256.New, secrets[i].Key[:])
		mac.Write(zeroed)
		sum := mac.Sum(nil)

		var computed [32]byte
		for j := range computed {
			computed[j] = sum[j] ^ clientRandom[j]
		}
		if subtle.ConstantTimeCompare(computed[:digestLen], make([]byte, digestLen)) == 1 {
			return i
		}
	}
	return -1
}

// parseMTProtoSecrets parses a comma-separated list of fake-TLS secrets
// (hex or base64, as produced by `proxy-server -gen-secret` or `mtg access`).
// Duplicates are dropped.
func parseMTProtoSecrets(raw string) ([]mtglib.Secret, error) {
	out := make([]mtglib.Secret, 0, 2)
	seen := make(map[[mtglib.SecretKeyLength]byte]struct{})

	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		secret, err := mtglib.ParseSecret(item)
		if err != nil {
			return nil, fmt.Errorf("secret %q: %w", item, err)
		}
		if _, dup := seen[secret.Key]; dup {
			continue
		}
		seen[secret.Key] = struct{}{}
		out = append(out, secret)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no MTProto secret configured")
	}
	return out, nil
}

// mtprotoEndpoint renders the host:port pair to put into share links. A
// wildcard listen address becomes the SERVER placeholder.
func mtprotoEndpoint(addr string) (host, port string, ok bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", false
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "SERVER"
	}
	return host, port, true
}

func mtprotoQuery(secret mtglib.Secret, addr string) (string, bool) {
	host, port, ok := mtprotoEndpoint(addr)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("server=%s&port=%s&secret=%s", host, port, secret.Hex()), true
}

// mtprotoLink renders a tg:// link for a secret.
func mtprotoLink(secret mtglib.Secret, addr string) string {
	query, ok := mtprotoQuery(secret, addr)
	if !ok {
		return ""
	}
	return "tg://proxy?" + query
}

// mtprotoWebLink renders the https://t.me/proxy form of the same link.
func mtprotoWebLink(secret mtglib.Secret, addr string) string {
	query, ok := mtprotoQuery(secret, addr)
	if !ok {
		return ""
	}
	return "https://t.me/proxy?" + query
}

// logMTProtoConfig prints the effective mtg configuration and the share
// links, so users see what mtg will actually use instead of guessed defaults.
func logMTProtoConfig(mc *MTProtoConfig, addr string) {
	host, port, _ := mtprotoEndpoint(addr)
	log.Printf("mtproto: ENABLED on %s:%s (shared with SOCKS5/HTTP), %d secret(s)", host, port, len(mc.Secrets))
	log.Printf("mtproto: concurrency=%d prefer-ip=%s fronting-port=%d idle=%s handshake=%s skew=%s",
		mc.effectiveConcurrency(), mc.effectivePreferIP(), mc.effectiveDomainFrontingPort(),
		mc.effectiveIdleTimeout(), mc.effectiveHandshakeTimeout(), mc.effectiveTolerateTimeSkewness())
	if mc.DomainFrontingHost != "" {
		log.Printf("mtproto: domain-fronting dial target override: %s", mc.DomainFrontingHost)
	}
	if mc.AutoUpdate {
		log.Printf("mtproto: Telegram DC list auto-update enabled")
	}

	for i := range mc.Secrets {
		secret := &mc.Secrets[i]
		log.Printf("mtproto: secret %d: %s (fronting host %s)", i+1, secret.Hex(), secret.Host)
		log.Printf("mtproto:   %s", mtprotoLink(*secret, addr))
		log.Printf("mtproto:   %s", mtprotoWebLink(*secret, addr))
	}
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

// isSOCKS5Greeting distinguishes a SOCKS5 greeting from a random header that
// happens to start with 0x05.
func isSOCKS5Greeting(br *bufio.Reader) bool {
	h, err := br.Peek(2)
	if err != nil || h[0] != socksVersion {
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
	for _, method := range b[2:] {
		if method == 0x00 || method == 0x02 {
			return true
		}
	}
	return false
}

// mtgLog returns the logger mtg internals use for this manager: mtg's own
// logging when verbose, silent otherwise.
func mtgLog(mc *MTProtoConfig) mtglib.Logger {
	return mc.newLogger()
}

func (mc *MTProtoConfig) newLogger() mtglib.Logger {
	if !mc.Verbose {
		return logger.NewNoopLogger()
	}
	return &mtgLogger{}
}

func (mc *MTProtoConfig) newEventStream() (mtglib.EventStream, func()) {
	if !mc.Verbose {
		return events.NewNoopStream(), func() {}
	}

	stream := events.NewEventStream([]events.ObserverFactory{
		func() events.Observer { return &mtgEventLogger{} },
	})
	return stream, stream.Shutdown
}

// mtgLogger adapts mtg's mtglib.Logger interface to the standard library
// logger, so mtg's messages (handshake errors, domain fronting, relay
// problems) land in the same output as the rest of the server.
type mtgLogger struct {
	name   string
	fields string
}

func (m *mtgLogger) Named(name string) mtglib.Logger {
	named := name
	if m.name != "" {
		named = m.name + "." + name
	}
	return &mtgLogger{name: named, fields: m.fields}
}

func (m *mtgLogger) bind(name, value string) mtglib.Logger {
	field := name + "=" + value
	if m.fields != "" {
		field = m.fields + " " + field
	}
	return &mtgLogger{name: m.name, fields: field}
}

func (m *mtgLogger) BindInt(name string, value int) mtglib.Logger {
	return m.bind(name, strconv.Itoa(value))
}

func (m *mtgLogger) BindStr(name, value string) mtglib.Logger  { return m.bind(name, value) }
func (m *mtgLogger) BindJSON(name, value string) mtglib.Logger { return m.bind(name, value) }

func (m *mtgLogger) write(level, format string, args ...any) {
	prefix := "mtproto"
	if m.name != "" {
		prefix += "." + m.name
	}
	line := fmt.Sprintf(format, args...)
	if m.fields != "" {
		log.Printf("[%s] %s: %s (%s)", prefix, level, line, m.fields)
		return
	}
	log.Printf("[%s] %s: %s", prefix, level, line)
}

func (m *mtgLogger) Printf(format string, args ...any) { m.write("info", format, args...) }
func (m *mtgLogger) Info(msg string)                   { m.write("info", "%s", msg) }
func (m *mtgLogger) InfoError(msg string, err error)   { m.write("info", "%s: %v", msg, err) }
func (m *mtgLogger) Warning(msg string)                { m.write("warn", "%s", msg) }
func (m *mtgLogger) WarningError(msg string, err error) {
	m.write("warn", "%s: %v", msg, err)
}
func (m *mtgLogger) Debug(msg string)                 { m.write("debug", "%s", msg) }
func (m *mtgLogger) DebugError(msg string, err error) { m.write("debug", "%s: %v", msg, err) }

// mtgEventLogger prints the mtg event stream in verbose mode: stream
// lifecycle, DC selection, domain fronting and replay attacks. Traffic events
// are dropped because they are far too chatty for a log line each.
type mtgEventLogger struct{}

func (mtgEventLogger) EventStart(e mtglib.EventStart) {
	log.Printf("[mtproto] stream %s started from %s", e.StreamID(), e.RemoteIP)
}

func (mtgEventLogger) EventFinish(e mtglib.EventFinish) {
	log.Printf("[mtproto] stream %s finished", e.StreamID())
}

func (mtgEventLogger) EventConnectedToDC(e mtglib.EventConnectedToDC) {
	log.Printf("[mtproto] stream %s connected to DC%d (%s)", e.StreamID(), e.DC, e.RemoteIP)
}

func (mtgEventLogger) EventDomainFronting(e mtglib.EventDomainFronting) {
	log.Printf("[mtproto] stream %s forwarded to the domain-fronting host", e.StreamID())
}

func (mtgEventLogger) EventTraffic(mtglib.EventTraffic) {}

func (mtgEventLogger) EventConcurrencyLimited(mtglib.EventConcurrencyLimited) {
	log.Printf("[mtproto] connection rejected: concurrency limit reached")
}

func (mtgEventLogger) EventIPBlocklisted(e mtglib.EventIPBlocklisted) {
	log.Printf("[mtproto] IP %s rejected by the ip lists", e.RemoteIP)
}

func (mtgEventLogger) EventReplayAttack(e mtglib.EventReplayAttack) {
	log.Printf("[mtproto] replay attack detected on stream %s", e.StreamID())
}

func (mtgEventLogger) EventIPListSize(e mtglib.EventIPListSize) {
	log.Printf("[mtproto] ip list updated (size=%d, blocklist=%t)", e.Size, e.IsBlockList)
}

func (mtgEventLogger) Shutdown() {}
