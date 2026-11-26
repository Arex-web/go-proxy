package main

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Username string
	Password string
	Timeout  time.Duration
	Verbose  bool

	// MTProto is nil when the Telegram proxy is disabled.
	MTProto *MTProtoConfig
}

func (c *Config) authEnabled() bool { return c.Username != "" }

// checkSOCKS5Auth verifies username/password (RFC 1929, constant-time compare)
func (c *Config) checkSOCKS5Auth(user, pass string) bool {
	if !c.authEnabled() {
		return true
	}
	uOK := subtle.ConstantTimeCompare([]byte(user), []byte(c.Username)) == 1
	pOK := subtle.ConstantTimeCompare([]byte(pass), []byte(c.Password)) == 1
	return uOK && pOK
}

// checkHTTPAuth verifies Proxy-Authorization: Basic <base64>
func (c *Config) checkHTTPAuth(headerVal string) bool {
	if !c.authEnabled() {
		return true
	}
	if !strings.HasPrefix(headerVal, "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(headerVal[6:]))
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	return c.checkSOCKS5Auth(parts[0], parts[1])
}

// bufferedConn couples a net.Conn with its peek buffer
type bufferedConn struct {
	net.Conn
	R *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.R.Read(p) }

func listen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// isClosedError reports whether an Accept error just means the listener was
// closed during shutdown.
func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection")
}

// envOr returns the environment value of key, or def when it is unset/empty.
func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// envUint parses an unsigned integer from the environment, falling back to
// def on absence or parse errors.
func envUint(key string, def uint) uint {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return def
	}
	return uint(value)
}

// envBool parses common truthy/falsy spellings; anything else yields def.
func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	}
	return def
}

// envDuration parses a Go duration (30s, 5m, 1h); anything else yields def.
func envDuration(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return def
	}
	return value
}
