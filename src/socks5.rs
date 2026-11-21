use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use crate::config::Config;
use crate::conn::{dial_tcp, tunnel, Conn};

const SOCKS_VERSION: u8 = 0x05;

const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NO_ACCEPT: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REPLY_SUCCEED: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_CONN_REFUSED: u8 = 0x05;
const REPLY_CMD_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDR_NOT_SUPPORTED: u8 = 0x08;

const AUTH_VERSION: u8 = 0x01;
const AUTH_SUCCESS: u8 = 0x00;
const AUTH_FAILURE: u8 = 0x01;

pub fn handle_socks5(conn: &mut Conn, cfg: &Config) {
    // --- Handshake: VER NMETHODS METHODS ---
    let mut header = [0u8; 2];
    if conn.read_exact(&mut header).is_err() {
        return;
    }
    if header[0] != SOCKS_VERSION {
        return;
    }
    let n_methods = header[1] as usize;
    let mut methods = vec![0u8; n_methods];
    if conn.read_exact(&mut methods).is_err() {
        return;
    }

    // Pick auth method.
    let chosen = if cfg.auth_enabled() {
        methods.iter().copied().find(|m| *m == METHOD_USER_PASS)
    } else {
        methods.iter().copied().find(|m| *m == METHOD_NO_AUTH)
    };

    let chosen = match chosen {
        Some(m) => m,
        None => {
            let _ = conn.write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPT]);
            if cfg.verbose {
                crate::log::info(&format!(
                    "[socks5] no acceptable methods from {}",
                    peer(conn)
                ));
            }
            return;
        }
    };
    if conn.write_all(&[SOCKS_VERSION, chosen]).is_err() {
        return;
    }

    // --- Username/Password subnegotiation (RFC 1929) ---
    if chosen == METHOD_USER_PASS {
        let mut ah = [0u8; 2];
        if conn.read_exact(&mut ah).is_err() || ah[0] != AUTH_VERSION {
            return;
        }
        let mut ubuf = vec![0u8; ah[1] as usize];
        if conn.read_exact(&mut ubuf).is_err() {
            return;
        }
        let mut plen_buf = [0u8; 1];
        if conn.read_exact(&mut plen_buf).is_err() {
            return;
        }
        let mut pbuf = vec![0u8; plen_buf[0] as usize];
        if conn.read_exact(&mut pbuf).is_err() {
            return;
        }

        let user = String::from_utf8_lossy(&ubuf).into_owned();
        if !cfg.check_socks5_auth(&ubuf, &pbuf) {
            let _ = conn.write_all(&[AUTH_VERSION, AUTH_FAILURE]);
            if cfg.verbose {
                crate::log::info(&format!(
                    "[socks5] auth FAILED user={} from {}",
                    user,
                    peer(conn)
                ));
            }
            return;
        }
        if conn.write_all(&[AUTH_VERSION, AUTH_SUCCESS]).is_err() {
            return;
        }
        if cfg.verbose {
            crate::log::info(&format!("[socks5] auth OK user={} from {}", user, peer(conn)));
        }
    }

    // --- Request: VER CMD RSV ATYP DST.ADDR DST.PORT ---
    let mut req_head = [0u8; 4];
    if conn.read_exact(&mut req_head).is_err() {
        return;
    }
    if req_head[0] != SOCKS_VERSION {
        let _ = send_reply(conn, REPLY_GENERAL_FAILURE, None);
        return;
    }
    let cmd = req_head[1];
    let atyp = req_head[3];

    let (dest_addr, dest_port) = match read_socks_addr(conn, atyp) {
        Some(v) => v,
        None => {
            let _ = send_reply(conn, REPLY_ADDR_NOT_SUPPORTED, None);
            return;
        }
    };
    let dial_addr = join_host_port(&dest_addr, dest_port);

    match cmd {
        CMD_CONNECT => do_socks_connect(conn, &dial_addr, cfg),
        CMD_UDP => do_socks_udp_associate(conn, cfg),
        _ => {
            let _ = send_reply(conn, REPLY_CMD_NOT_SUPPORTED, None);
            if cfg.verbose {
                crate::log::info(&format!(
                    "[socks5] unsupported CMD={} from {}",
                    cmd,
                    peer(conn)
                ));
            }
        }
    }
}

/// Read DST.ADDR + DST.PORT for the given ATYP.
fn read_socks_addr(conn: &mut Conn, atyp: u8) -> Option<(String, u16)> {
    match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            conn.read_exact(&mut b).ok()?;
            let port = read_u16(conn)?;
            Some((Ipv4Addr::from(b).to_string(), port))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            conn.read_exact(&mut len).ok()?;
            let mut host = vec![0u8; len[0] as usize];
            conn.read_exact(&mut host).ok()?;
            let port = read_u16(conn)?;
            Some((String::from_utf8_lossy(&host).into_owned(), port))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            conn.read_exact(&mut b).ok()?;
            let port = read_u16(conn)?;
            Some((Ipv6Addr::from(b).to_string(), port))
        }
        _ => None,
    }
}

fn read_u16(conn: &mut Conn) -> Option<u16> {
    let mut b = [0u8; 2];
    conn.read_exact(&mut b).ok()?;
    Some(u16::from_be_bytes(b))
}

/// Send a SOCKS5 reply with the bound address (or zeros when unknown).
fn send_reply(conn: &mut Conn, rep: u8, bind_addr: Option<SocketAddr>) -> io::Result<()> {
    let mut buf = vec![SOCKS_VERSION, rep, 0x00];

    match bind_addr {
        Some(SocketAddr::V4(v4)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
        None => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&[0, 0, 0, 0]);
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
    }

    conn.write_all(&buf)
}

fn do_socks_connect(client: &mut Conn, dial_addr: &str, cfg: &Config) {
    let remote: TcpStream = match dial_tcp(dial_addr, cfg.timeout) {
        Ok(s) => s,
        Err(e) => {
            let _ = send_reply(client, REPLY_CONN_REFUSED, None);
            if cfg.verbose {
                crate::log::info(&format!(
                    "[socks5 CONNECT] -> {} failed: {}",
                    dial_addr, e
                ));
            }
            return;
        }
    };

    let local = client.local_addr().ok();
    let _ = send_reply(client, REPLY_SUCCEED, local);
    if cfg.verbose {
        crate::log::info(&format!(
            "[socks5 CONNECT] {} -> {}",
            peer(client),
            dial_addr
        ));
    }

    // Long-lived tunnel from here on.
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);

    tunnel(client, remote);
}

/// UDP ASSOCIATE: reply with a UDP relay address, then relay encapsulated packets.
fn do_socks_udp_associate(client: &mut Conn, cfg: &Config) {
    let udp_srv = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(s) => s,
        Err(_) => {
            let _ = send_reply(client, REPLY_GENERAL_FAILURE, None);
            return;
        }
    };

    let bound_port = udp_srv.local_addr().map(|a| a.port()).unwrap_or(0);
    // Advertise the TCP local IP with the UDP relay port.
    let reply_addr = client
        .local_addr()
        .ok()
        .map(|a| SocketAddr::new(a.ip(), bound_port));
    let _ = send_reply(client, REPLY_SUCCEED, reply_addr);
    if cfg.verbose {
        crate::log::info(&format!(
            "[socks5 UDP] {} -> udp-relay 0.0.0.0:{}",
            peer(client),
            bound_port
        ));
    }

    // --- UDP -> TCP direction: receive datagrams, encapsulate, write to client ---
    let udp_to_tcp = {
        let udp_srv = match udp_srv.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut client_w = match client.try_clone_stream() {
            Ok(s) => s,
            Err(_) => return,
        };
        std::thread::spawn(move || {
            let mut buf = [0u8; 65535];
            loop {
                let (n, src) = match udp_srv.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if client_w.write_all(&encode_udp_packet(src, &buf[..n])).is_err() {
                    return;
                }
            }
        })
    };

    // --- TCP -> UDP direction: parse encapsulated packets from client ---
    loop {
        let mut head = [0u8; 3]; // RSV(2) FRAG(1)
        if client.read_exact(&mut head).is_err() {
            break;
        }
        let frag = head[2];

        let mut atyp = [0u8; 1];
        if client.read_exact(&mut atyp).is_err() {
            break;
        }

        let dest = match read_socks_addr(client, atyp[0]) {
            Some((host, port)) => (host, port),
            None => break,
        };
        if frag != 0 {
            // Fragmentation unsupported and we cannot resync without a length.
            break;
        }

        // Payload: read whatever is currently available (short drain window).
        let payload = drain_payload(client);
        if payload.is_empty() {
            continue;
        }

        let dest_socket = match resolve_udp(&dest.0, dest.1) {
            Some(s) => s,
            None => continue,
        };
        let _ = udp_srv.send_to(&payload, dest_socket);
    }

    drop(udp_to_tcp);
}

/// Build a SOCKS5 UDP header (RSV FRAG ATYP ADDR PORT) + payload.
fn encode_udp_packet(src: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00, 0x00];
    match src.ip() {
        IpAddr::V4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&src.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn resolve_udp(host: &str, port: u16) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    join_host_port(host, port).to_socket_addrs().ok()?.next()
}

/// Read currently-available payload bytes (bounded by a short read timeout).
fn drain_payload(client: &mut Conn) -> Vec<u8> {
    let _ = client.set_read_timeout(Some(Duration::from_millis(15)));
    let mut payload = Vec::with_capacity(1500);
    let mut tmp = [0u8; 1500];
    loop {
        match client.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                payload.extend_from_slice(&tmp[..n]);
                if n < tmp.len() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = client.set_read_timeout(None);
    payload
}

fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn peer(conn: &Conn) -> String {
    conn.peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".to_string())
}