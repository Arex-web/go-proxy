use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::config::Config;
use crate::conn::{dial_tcp, tunnel, Conn};

/// Hop-by-hop headers that must not be forwarded to the upstream.
const HOP_BY_HOP: [&str; 8] = [
    "proxy-authorization",
    "proxy-connection",
    "proxy-authenticate",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
];

/// HTTP forward proxy: CONNECT tunnels + absolute-URI request forwarding.
pub fn handle_http(conn: &mut Conn, cfg: &Config) {
    // Clear the sniff deadline; tunnels are long-lived.
    let _ = conn.set_read_timeout(None);
    let _ = conn.set_write_timeout(None);

    let request_line = match conn.read_line() {
        Ok(Some(l)) if !l.is_empty() => l,
        _ => {
            if cfg.verbose {
                crate::log::info(&format!(
                    "[http] bad request from {}",
                    peer(conn)
                ));
            }
            return;
        }
    };

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        match conn.read_line() {
            Ok(Some(line)) if line.is_empty() => break,
            Ok(Some(line)) => {
                if let Some(idx) = line.find(':') {
                    let name = line[..idx].trim().to_string();
                    let value = line[idx + 1..].trim().to_string();
                    headers.push((name, value));
                }
            }
            _ => return,
        }
    }

    let header = |name: &str| -> Option<&str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };

    // --- Auth check ---
    if !cfg.check_http_auth(header("proxy-authorization").unwrap_or("")) {
        let _ = conn.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"proxy\"\r\n\
              Content-Length: 0\r\n\r\n",
        );
        if cfg.verbose {
            crate::log::info(&format!(
                "[http] auth FAILED {} {} from {}",
                method,
                target,
                peer(conn)
            ));
        }
        return;
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(conn, &target, header("host"), cfg);
        return;
    }

    // --- Regular absolute-URI proxying: GET http://example.com/path HTTP/1.1 ---
    let uri = match parse_absolute_uri(&target) {
        Some(u) => u,
        None => {
            let _ = conn.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    };
    do_http_forward(conn, &method, &version, &uri, &headers, cfg);
}

struct Uri {
    host: String,
    port: u16,
    path: String,
    default_port: u16,
}

/// Parse `http://host[:port][/path][?query]` into its pieces.
fn parse_absolute_uri(target: &str) -> Option<Uri> {
    let (scheme, rest) = target.split_once("://")?;
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };

    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }

    // Strip userinfo, if any.
    let authority = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };

    let (host, port) = if authority.starts_with('[') {
        // IPv6 literal: [::1]:8080
        let end = authority.find(']')?;
        let host = &authority[1..end];
        let port = authority[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(port) => (h.to_string(), port),
                Err(_) => (authority.to_string(), default_port),
            },
            None => (authority.to_string(), default_port),
        }
    };

    let path = if path.is_empty() { "/".to_string() } else { path.to_string() };

    Some(Uri {
        host,
        port,
        path,
        default_port,
    })
}

fn handle_connect(conn: &mut Conn, target: &str, host_header: Option<&str>, cfg: &Config) {
    let authority = if !target.is_empty() {
        target.to_string()
    } else {
        host_header.unwrap_or("").to_string()
    };

    let dial_to = if authority.contains(':') {
        authority.clone()
    } else {
        format!("{}:443", authority)
    };

    let remote: TcpStream = match dial_tcp(&dial_to, cfg.timeout) {
        Ok(s) => s,
        Err(e) => {
            let _ = conn.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            if cfg.verbose {
                crate::log::info(&format!("[http CONNECT] -> {} failed: {}", dial_to, e));
            }
            return;
        }
    };

    let _ = conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
    if cfg.verbose {
        crate::log::info(&format!(
            "[http CONNECT] {} -> {}",
            peer(conn),
            dial_to
        ));
    }

    tunnel(conn, remote);
}

/// Forward a plain-HTTP request upstream and stream the response back.
fn do_http_forward(
    client: &mut Conn,
    method: &str,
    version: &str,
    uri: &Uri,
    headers: &[(String, String)],
    cfg: &Config,
) {
    let dial_to = format!("{}:{}", uri.host, uri.port);
    let remote = match dial_tcp(&dial_to, cfg.timeout) {
        Ok(s) => s,
        Err(e) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            if cfg.verbose {
                crate::log::info(&format!(
                    "[http] forward {} {} failed: {}",
                    method, dial_to, e
                ));
            }
            return;
        }
    };
    let mut remote = match Conn::new(remote) {
        Ok(c) => c,
        Err(_) => return,
    };

    // --- Rebuild the request in origin-form, without hop-by-hop headers ---
    let mut out = String::new();
    out.push_str(&format!("{} {} {}\r\n", method, uri.path, version));

    let mut has_host = false;
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) {
            continue;
        }
        if lower == "host" {
            has_host = true;
        }
        out.push_str(&format!("{}: {}\r\n", name, value));
    }
    if !has_host {
        let host_header = if uri.port == uri.default_port {
            uri.host.clone()
        } else if uri.host.contains(':') {
            format!("[{}]:{}", uri.host, uri.port)
        } else {
            format!("{}:{}", uri.host, uri.port)
        };
        out.push_str(&format!("Host: {}\r\n", host_header));
    }
    // Upstream connection is one-shot; the response body is then EOF-delimited.
    out.push_str("Connection: close\r\n\r\n");

    if remote.write_all(out.as_bytes()).is_err() {
        return;
    }

    // Stream the request body, if any.
    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<u64>().ok());

    if let Some(len) = content_length {
        if len > 0 && io::copy(&mut (&mut *client).take(len), &mut remote).is_err() {
            return;
        }
    }

    // --- Relay the response: status line + headers + body (until EOF) ---
    let status_line = match remote.read_line() {
        Ok(Some(l)) => l,
        _ => return,
    };
    if client
        .write_all(format!("{}\r\n", status_line).as_bytes())
        .is_err()
    {
        return;
    }

    loop {
        let line = match remote.read_line() {
            Ok(Some(l)) => l,
            _ => return,
        };
        if line.is_empty() {
            break;
        }
        let lower = line
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || lower == "transfer-encoding" {
            continue;
        }
        if client
            .write_all(format!("{}\r\n", line).as_bytes())
            .is_err()
        {
            return;
        }
    }
    if client.write_all(b"\r\n").is_err() {
        return;
    }

    if cfg.verbose {
        crate::log::info(&format!(
            "[http] {} {} -> {}",
            method, uri.path, status_line
        ));
    }

    let _ = io::copy(&mut remote, &mut *client);
}

fn peer(conn: &Conn) -> String {
    conn.peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".to_string())
}