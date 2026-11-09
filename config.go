package main

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"strings"
	"time"
)

type Config struct {
	Username string
	Password string
	Timeout  time.Duration
	Verbose  bool
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
