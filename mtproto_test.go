package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/9seconds/mtg/v2/mtglib"
)

func TestParseMTProtoSecrets(t *testing.T) {
	first := mtglib.GenerateSecret("www.google.com")
	second := mtglib.GenerateSecret("example.com")

	secrets, err := parseMTProtoSecrets(first.Hex() + "," + second.Base64())
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("got %d secrets", len(secrets))
	}
	if secrets[0].Host != "www.google.com" {
		t.Fatalf("bad host %q", secrets[0].Host)
	}
	if secrets[1].Host != "example.com" {
		t.Fatalf("bad host %q", secrets[1].Host)
	}

	// The same secret in hex and base64 must collapse into one entry.
	secrets, err = parseMTProtoSecrets(first.Hex() + "," + first.Base64())
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 {
		t.Fatalf("duplicate secret was not dropped: %d", len(secrets))
	}

	if _, err := parseMTProtoSecrets("nothex"); err == nil {
		t.Fatal("expected error for non-hex")
	}
	if _, err := parseMTProtoSecrets(""); err == nil {
		t.Fatal("expected error for empty")
	}
}

// buildFakeTLSHello builds a minimal TLS ClientHello record with the
// fake-TLS HMAC in its random field, the way a Telegram client does it.
func buildFakeTLSHello(t *testing.T, secret mtglib.Secret) []byte {
	t.Helper()

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32)) // random placeholder
	sessionID := make([]byte, 32)
	body.WriteByte(byte(len(sessionID)))
	body.Write(sessionID)
	body.Write([]byte{0x00, 0x02, 0x13, 0x01})
	body.Write([]byte{0x01, 0x00})
	body.Write([]byte{0x00, 0x00})

	var handshake bytes.Buffer
	handshake.WriteByte(0x01)
	handshake.Write([]byte{byte(body.Len() >> 16), byte(body.Len() >> 8), byte(body.Len())})
	handshake.Write(body.Bytes())

	hello := make([]byte, 0, 5+handshake.Len())
	hello = append(hello, 0x16, 0x03, 0x01)
	hello = append(hello, byte(handshake.Len()>>8), byte(handshake.Len()))
	hello = append(hello, handshake.Bytes()...)

	// HMAC over the hello with the random field zeroed, keyed with the secret.
	var zeroed bytes.Buffer
	zeroed.Write(hello[:11])
	zeroed.Write(make([]byte, 32))
	zeroed.Write(hello[43:])
	mac := hmac.New(sha256.New, secret.Key[:])
	mac.Write(zeroed.Bytes())
	copy(hello[11:43], mac.Sum(nil))

	return hello
}

func TestMatchFakeTLS(t *testing.T) {
	secret := mtglib.GenerateSecret("www.google.com")
	hello := buildFakeTLSHello(t, secret)

	br := bufio.NewReaderSize(bytes.NewReader(hello), len(hello))
	if idx := matchMTProtoFakeTLS(br, []mtglib.Secret{secret}); idx != 0 {
		t.Fatalf("expected match 0, got %d", idx)
	}

	other := mtglib.GenerateSecret("example.com")
	br = bufio.NewReaderSize(bytes.NewReader(hello), len(hello))
	if idx := matchMTProtoFakeTLS(br, []mtglib.Secret{other}); idx != -1 {
		t.Fatalf("expected no match, got %d", idx)
	}
}

func TestMatchFakeTLSRejectsPlainTLS(t *testing.T) {
	secret := mtglib.GenerateSecret("www.google.com")
	hello := buildFakeTLSHello(t, mtglib.GenerateSecret("plain.example.com"))

	// A real TLS ClientHello must not be mistaken for MTProto traffic.
	br := bufio.NewReaderSize(bytes.NewReader(hello), len(hello))
	if idx := matchMTProtoFakeTLS(br, []mtglib.Secret{secret}); idx != -1 {
		t.Fatalf("plain TLS matched secret %d", idx)
	}

	// Random bytes are not a ClientHello.
	br = bufio.NewReaderSize(bytes.NewReader([]byte{0x16, 0x03, 0x01}), 8)
	if idx := matchMTProtoFakeTLS(br, []mtglib.Secret{secret}); idx != -1 {
		t.Fatalf("truncated hello matched secret %d", idx)
	}
}

func TestMTProtoLinks(t *testing.T) {
	secret := mtglib.GenerateSecret("www.google.com")

	tg := mtprotoLink(secret, "0.0.0.0:1080")
	if !strings.HasPrefix(tg, "tg://proxy?server=SERVER&port=1080&secret="+secret.Hex()) {
		t.Fatalf("bad tg link %q", tg)
	}

	web := mtprotoWebLink(secret, "203.0.113.7:443")
	if !strings.HasPrefix(web, "https://t.me/proxy?server=203.0.113.7&port=443&secret="+secret.Hex()) {
		t.Fatalf("bad web link %q", web)
	}

	if got := mtprotoLink(secret, "not-an-address"); got != "" {
		t.Fatalf("expected no link, got %q", got)
	}
}

func TestMTProtoConfigValidate(t *testing.T) {
	secret := mtglib.GenerateSecret("www.google.com")

	cfg := &MTProtoConfig{Secrets: []mtglib.Secret{secret}, PreferIP: "prefer-ipv7"}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for invalid prefer-ip")
	}

	cfg.PreferIP = "only-ipv4"
	if err := cfg.validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg.PreferIP = ""
	if err := cfg.validate(); err != nil {
		t.Fatalf("default prefer-ip rejected: %v", err)
	}

	empty := &MTProtoConfig{}
	if err := empty.validate(); err == nil {
		t.Fatal("expected error without secrets")
	}
}

func TestMTGLogger(t *testing.T) {
	var logger mtglib.Logger = &mtgLogger{name: "relay"}
	logger = logger.BindStr("ip", "127.0.0.1").BindInt("dc", 2)
	logger.Info("stream started")
	logger.InfoError("stream failed", nil)
}
