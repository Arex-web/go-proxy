package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/9seconds/mtg/v2/mtglib"
)

func TestParseMTProtoSecrets(t *testing.T) {
	sec := mtglib.GenerateSecret("www.google.com")
	hex := sec.Hex()
	b64 := sec.Base64()

	secrets, err := parseMTProtoSecrets(hex + "," + b64)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("got %d secrets", len(secrets))
	}
	if secrets[0].Host != "www.google.com" {
		t.Fatalf("bad host %q", secrets[0].Host)
	}

	if _, err := parseMTProtoSecrets("nothex"); err == nil {
		t.Fatal("expected error for non-hex")
	}
	if _, err := parseMTProtoSecrets(""); err == nil {
		t.Fatal("expected error for empty")
	}
}

func TestMatchObfuscated2(t *testing.T) {
	sec := mtglib.GenerateSecret("www.google.com")

	// Build a valid obfuscated2 frame the way a client would.
	var frame [64]byte
	if _, err := rand.Read(frame[:]); err != nil {
		t.Fatal(err)
	}
	frame[0] = 0x42
	binary.LittleEndian.PutUint32(frame[56:60], 0xdddddddd)
	binary.LittleEndian.PutUint16(frame[60:62], 2)

	var buf [48]byte
	copy(buf[:32], frame[8:40])
	copy(buf[32:], sec.Key[:])
	sendKey := sha256.Sum256(buf[:])
	// The client encrypts bytes 56..63 with SHA256(key||secret); the proxy
	// validates by decrypting with the same key. Encrypt so the tag is hidden.
	block, _ := aes.NewCipher(sendKey[:])
	enc := cipher.NewCTR(block, frame[40:56])
	var scratch [64]byte
	copy(scratch[:], frame[:])
	enc.XORKeyStream(scratch[:], scratch[:])
	copy(frame[56:], scratch[56:])

	br := bufio.NewReaderSize(bytes.NewReader(frame[:]), 64)
	if idx := matchMTProtoObfuscated2(br, []mtglib.Secret{sec}); idx != 0 {
		t.Fatalf("expected match 0, got %d", idx)
	}

	// A different secret must not match.
	other := mtglib.GenerateSecret("example.com")
	br = bufio.NewReaderSize(bytes.NewReader(frame[:]), 64)
	if idx := matchMTProtoObfuscated2(br, []mtglib.Secret{other}); idx != -1 {
		t.Fatalf("expected no match, got %d", idx)
	}
}

func TestMatchFakeTLS(t *testing.T) {
	sec := mtglib.GenerateSecret("www.google.com")

	// Minimal TLS ClientHello record with an HMAC random field.
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32)) // random placeholder
	sid := make([]byte, 32)
	body.WriteByte(byte(len(sid)))
	body.Write(sid)
	body.Write([]byte{0x00, 0x02, 0x13, 0x01})
	body.Write([]byte{0x01, 0x00})
	body.Write([]byte{0x00, 0x00})

	var hs bytes.Buffer
	hs.WriteByte(0x01)
	hs.Write([]byte{byte(body.Len() >> 16), byte(body.Len() >> 8), byte(body.Len())})
	hs.Write(body.Bytes())

	hello := make([]byte, 0, 5+hs.Len())
	hello = append(hello, 0x16, 0x03, 0x01)
	hello = append(hello, byte(hs.Len()>>8), byte(hs.Len()))
	hello = append(hello, hs.Bytes()...)

	// HMAC over the hello (random zeroed) keyed with the secret.
	var zeroed bytes.Buffer
	zeroed.Write(hello[:11])
	zeroed.Write(make([]byte, 32))
	zeroed.Write(hello[43:])
	mac := hmac.New(sha256.New, sec.Key[:])
	mac.Write(zeroed.Bytes())
	copy(hello[11:43], mac.Sum(nil))

	br := bufio.NewReaderSize(bytes.NewReader(hello), len(hello))
	if idx := matchMTProtoFakeTLS(br, []mtglib.Secret{sec}); idx != 0 {
		t.Fatalf("expected match 0, got %d", idx)
	}

	other := mtglib.GenerateSecret("example.com")
	br = bufio.NewReaderSize(bytes.NewReader(hello), len(hello))
	if idx := matchMTProtoFakeTLS(br, []mtglib.Secret{other}); idx != -1 {
		t.Fatalf("expected no match, got %d", idx)
	}
}
