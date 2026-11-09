package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// SOCKS5 per RFC 1928 / RFC 1929
const (
	socksVersion       = 0x05
	socksMethodNoAuth  = 0x00
	socksMethodUserPass = 0x02
	socksMethodNoAccept = 0xFF

	socksCmdConnect = 0x01
	socksCmdBind    = 0x02
	socksCmdUDP     = 0x03

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksReplySucceed            = 0x00
	socksReplyGeneralFailure     = 0x01
	socksReplyNotAllowed         = 0x02
	socksReplyNetworkUnreachable = 0x03
	socksReplyHostUnreachable    = 0x04
	socksReplyConnRefused        = 0x05
	socksReplyTTLExpired         = 0x06
	socksReplyCmdNotSupported    = 0x07
	socksReplyAddrNotSupported   = 0x08

	authVersion = 0x01
	authSuccess = 0x00
	authFailure = 0x01
)

func handleSOCKS5(conn *bufferedConn, cfg *Config) {
	// --- Handshake: read VER NMETHODS METHODS ---
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != socksVersion {
		return
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Pick auth method
	chosen := byte(socksMethodNoAccept)
	if cfg.authEnabled() {
		for _, m := range methods {
			if m == socksMethodUserPass {
				chosen = socksMethodUserPass
				break
			}
		}
	} else {
		for _, m := range methods {
			if m == socksMethodNoAuth {
				chosen = socksMethodNoAuth
				break
			}
		}
	}
	if chosen == socksMethodNoAccept {
		_, _ = conn.Write([]byte{socksVersion, socksMethodNoAccept})
		if cfg.Verbose {
			log.Printf("[socks5] no acceptable methods from %s", conn.RemoteAddr())
		}
		return
	}
	if _, err := conn.Write([]byte{socksVersion, chosen}); err != nil {
		return
	}

	// --- Username/Password subnegotiation (RFC 1929) ---
	if chosen == socksMethodUserPass {
		ah := make([]byte, 2)
		if _, err := io.ReadFull(conn, ah); err != nil {
			return
		}
		if ah[0] != authVersion {
			return
		}
		ulen := int(ah[1])
		ubuf := make([]byte, ulen)
		if _, err := io.ReadFull(conn, ubuf); err != nil {
			return
		}
		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, plenBuf); err != nil {
			return
		}
		plen := int(plenBuf[0])
		pbuf := make([]byte, plen)
		if _, err := io.ReadFull(conn, pbuf); err != nil {
			return
		}
		user, pass := string(ubuf), string(pbuf)
		if !cfg.checkSOCKS5Auth(user, pass) {
			_, _ = conn.Write([]byte{authVersion, authFailure})
			if cfg.Verbose {
				log.Printf("[socks5] auth FAILED user=%s from %s", user, conn.RemoteAddr())
			}
			return
		}
		if _, err := conn.Write([]byte{authVersion, authSuccess}); err != nil {
			return
		}
		if cfg.Verbose {
			log.Printf("[socks5] auth OK user=%s from %s", user, conn.RemoteAddr())
		}
	}

	// --- Request: VER CMD RSV ATYP DST.ADDR DST.PORT ---
	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHead); err != nil {
		return
	}
	if reqHead[0] != socksVersion {
		_ = sendSOCKSReply(conn, socksReplyGeneralFailure, nil)
		return
	}
	cmd := reqHead[1]
	atyp := reqHead[3]

	destAddr, destPort, err := readSOCKSAddr(conn, atyp)
	if err != nil {
		_ = sendSOCKSReply(conn, socksReplyAddrNotSupported, nil)
		return
	}
	dialAddr := net.JoinHostPort(destAddr, strconv.Itoa(destPort))

	switch cmd {
	case socksCmdConnect:
		doSOCKSConnect(conn, dialAddr, cfg)
	case socksCmdUDP:
		doSOCKSUDPAssociate(conn, cfg)
	default:
		_ = sendSOCKSReply(conn, socksReplyCmdNotSupported, nil)
		if cfg.Verbose {
			log.Printf("[socks5] unsupported CMD=%d from %s", cmd, conn.RemoteAddr())
		}
	}
}

func readSOCKSAddr(r io.Reader, atyp byte) (string, int, error) {
	switch atyp {
	case socksAtypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return "", 0, err
		}
		return net.IP(b).String(), int(binary.BigEndian.Uint16(portBuf)), nil
	case socksAtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", 0, err
		}
		host := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(r, host); err != nil {
			return "", 0, err
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return "", 0, err
		}
		return string(host), int(binary.BigEndian.Uint16(portBuf)), nil
	case socksAtypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return "", 0, err
		}
		return net.IP(b).String(), int(binary.BigEndian.Uint16(portBuf)), nil
	default:
		return "", 0, fmt.Errorf("unsupported ATYP %d", atyp)
	}
}

// localAddrForReply returns the local TCP address of conn as ATYP+addr+port
func sendSOCKSReply(conn net.Conn, rep byte, bindAddr *net.TCPAddr) error {
	var atyp byte
	var addrBytes []byte
	var port uint16

	if bindAddr != nil {
		if ip4 := bindAddr.IP.To4(); ip4 != nil {
			atyp = socksAtypIPv4
			addrBytes = []byte(ip4)
		} else {
			atyp = socksAtypIPv6
			addrBytes = []byte(bindAddr.IP.To16())
		}
		port = uint16(bindAddr.Port)
	} else {
		atyp = socksAtypIPv4
		addrBytes = []byte{0, 0, 0, 0}
		port = 0
	}
	buf := []byte{socksVersion, rep, 0x00, atyp}
	buf = append(buf, addrBytes...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	buf = append(buf, pb...)
	_, err := conn.Write(buf)
	return err
}

func doSOCKSConnect(client *bufferedConn, dialAddr string, cfg *Config) {
	d := net.Dialer{Timeout: cfg.Timeout}
	remote, err := d.Dial("tcp", dialAddr)
	if err != nil {
		_ = sendSOCKSReply(client, socksReplyConnRefused, nil)
		if cfg.Verbose {
			log.Printf("[socks5 CONNECT] -> %s failed: %v", dialAddr, err)
		}
		return
	}
	defer remote.Close()

	local := client.Conn.LocalAddr().(*net.TCPAddr)
	_ = sendSOCKSReply(client, socksReplySucceed, local)
	if cfg.Verbose {
		log.Printf("[socks5 CONNECT] %s -> %s", client.RemoteAddr(), dialAddr)
	}
	// Clear deadline for long-lived tunnel after handshake (use 0)
	_ = client.Conn.SetDeadline(time.Time{})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(remote, client); if tc, ok := remote.(*net.TCPConn); ok { _ = tc.CloseWrite() } }()
	go func() { defer wg.Done(); _, _ = io.Copy(client, remote); if tc, ok := client.Conn.(*net.TCPConn); ok { _ = tc.CloseWrite() } }()
	wg.Wait()
}

// UDP ASSOCIATE: replies with a UDP relay address, then relays encapsulated UDP packets.
func doSOCKSUDPAssociate(client *bufferedConn, cfg *Config) {
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		_ = sendSOCKSReply(client, socksReplyGeneralFailure, nil)
		return
	}
	udpSrv, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_ = sendSOCKSReply(client, socksReplyGeneralFailure, nil)
		return
	}
	defer udpSrv.Close()

	bound := udpSrv.LocalAddr().(*net.UDPAddr)
	// Use TCP local IP + UDP port
	tcpLocal := client.Conn.LocalAddr().(*net.TCPAddr)
	replyAddr := &net.TCPAddr{IP: tcpLocal.IP, Port: bound.Port}
	_ = sendSOCKSReply(client, socksReplySucceed, replyAddr)
	if cfg.Verbose {
		log.Printf("[socks5 UDP] %s -> udp-relay %s", client.RemoteAddr(), udpSrv.LocalAddr())
	}

	// Client -> destination (via TCP conn reader, encapsulated)
	// Destination -> client (via UDP socket, encapsulated back)
	// Both directions run until TCP closes.

	// UDP -> TCP direction: receive raw UDP, encapsulate, write to client
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := udpSrv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Build SOCKS UDP header: RSV(2) FRAG(1) ATYP ADDR PORT
			hdr := []byte{0x00, 0x00, 0x00}
			host, portStr, _ := net.SplitHostPort(src.String())
			if ip := net.ParseIP(host).To4(); ip != nil {
				hdr = append(hdr, socksAtypIPv4)
				hdr = append(hdr, []byte(ip)...)
			} else if ip := net.ParseIP(host); ip != nil {
				hdr = append(hdr, socksAtypIPv6)
				hdr = append(hdr, []byte(ip.To16())...)
			} else {
				hdr = append(hdr, socksAtypDomain, byte(len(host)))
				hdr = append(hdr, []byte(host)...)
			}
			port, _ := strconv.Atoi(portStr)
			pb := make([]byte, 2)
			binary.BigEndian.PutUint16(pb, uint16(port))
			hdr = append(hdr, pb...)
			hdr = append(hdr, buf[:n]...)
			if _, err := client.Conn.Write(hdr); err != nil {
				return
			}
		}
	}()

	// TCP -> UDP direction: parse encapsulated packet from client
	for {
		// RSV(2) FRAG(1)
		head := make([]byte, 3)
		if _, err := io.ReadFull(client, head); err != nil {
			break
		}
		frag := head[2]
		if frag != 0 {
			// Fragmentation not supported: consume rest? Simplest: abort.
			// To avoid stream desync, we drop this packet's payload.
			// (Full FRAG parsing would need to read the address first.)
			// We still need to parse address to skip payload correctly.
		}
		atyp := make([]byte, 1)
		if _, err := io.ReadFull(client, atyp); err != nil {
			break
		}
		// Reconstruct a reader that replays atyp byte for readSOCKSAddr? Simpler: parse manually.
		// We'll parse address inline here.
		var destHost string
		var destPort int
		switch atyp[0] {
		case socksAtypIPv4:
			b := make([]byte, 4)
			if _, err := io.ReadFull(client, b); err != nil { return }
			destHost = net.IP(b).String()
		case socksAtypIPv6:
			b := make([]byte, 16)
			if _, err := io.ReadFull(client, b); err != nil { return }
			destHost = net.IP(b).String()
		case socksAtypDomain:
			lb := make([]byte, 1)
			if _, err := io.ReadFull(client, lb); err != nil { return }
			hb := make([]byte, int(lb[0]))
			if _, err := io.ReadFull(client, hb); err != nil { return }
			destHost = string(hb)
		default:
			return
		}
		pb := make([]byte, 2)
		if _, err := io.ReadFull(client, pb); err != nil { return }
		destPort = int(binary.BigEndian.Uint16(pb))
		if frag != 0 {
			// Frag≠0: cannot reliably resync (no payload length). Terminate association.
			return
		}
		// Remaining bytes on this TCP read are payload. io.ReadFull can't know length,
		// so we read with a short deadline strategy: copy available data.
		// Approach: set a short deadline and read all currently buffered/available bytes.
		// For correctness with small datagrams (typical), read in a goroutine-copy fashion:
		// We use a 10ms drain read loop.
		_ = client.Conn.SetReadDeadline(timeNowPlus(15))
		payload := make([]byte, 0, 1500)
		tmp := make([]byte, 1500)
		for {
			n, err := client.Read(tmp)
			if n > 0 {
				payload = append(payload, tmp[:n]...)
			}
			if err != nil {
				break
			}
			// If we got less than buffer, likely datagram end; continue briefly
			if n < len(tmp) {
				break
			}
		}
		_ = client.Conn.SetReadDeadline(time.Time{})
		if len(payload) == 0 {
			continue
		}
		dst := &net.UDPAddr{IP: net.ParseIP(destHost), Port: destPort}
		if dst.IP == nil {
			// domain: resolve
			dst, _ = net.ResolveUDPAddr("udp", net.JoinHostPort(destHost, strconv.Itoa(destPort)))
			if dst == nil {
				continue
			}
		}
		_, _ = udpSrv.WriteToUDP(payload, dst)
	}
	_ = udpSrv.Close()
}

func timeNowPlus(ms int) time.Time {
	return time.Now().Add(time.Duration(ms) * time.Millisecond)
}
