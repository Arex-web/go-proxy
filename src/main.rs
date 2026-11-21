mod config;
mod conn;
mod env;
mod httpproxy;
mod log;
mod socks5;

use std::net::TcpListener;
use std::process::exit;
use std::time::Duration;

use config::Config;
use conn::Conn;

/// Mirror of Go's `os.Getenv(key)` with a fallback default.
fn env_or(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => default.to_string(),
    }
}

fn main() {
    env::load_env();

    let mut addr = env_or("PROXY_ADDR", "0.0.0.0:1080");
    let mut username = env_or("PROXY_USERNAME", "");
    let mut password = env_or("PROXY_PASSWORD", "");
    let mut timeout = Duration::from_secs(30);
    let mut verbose = false;

    // Minimal flag parsing, mirroring the Go version:
    //   -addr / -username / -password / -timeout / -v
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let (flag, inline_val) = match arg.split_once('=') {
            Some((f, v)) => (f.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        let take_value = |i: &mut usize| -> Option<String> {
            if let Some(v) = inline_val.clone() {
                return Some(v);
            }
            if *i + 1 < args.len() {
                *i += 1;
                return Some(args[*i].clone());
            }
            None
        };

        match flag.as_str() {
            "-addr" | "--addr" => {
                if let Some(v) = take_value(&mut i) {
                    addr = v;
                }
            }
            "-username" | "--username" => {
                if let Some(v) = take_value(&mut i) {
                    username = v;
                }
            }
            "-password" | "--password" => {
                if let Some(v) = take_value(&mut i) {
                    password = v;
                }
            }
            "-timeout" | "--timeout" => {
                if let Some(v) = take_value(&mut i) {
                    match parse_duration(&v) {
                        Some(d) => timeout = d,
                        None => {
                            log::error(&format!("invalid timeout: {}", v));
                            exit(2);
                        }
                    }
                }
            }
            "-v" | "--v" | "-verbose" | "--verbose" => verbose = true,
            "-h" | "--help" => {
                print_usage();
                return;
            }
            _ => {
                log::error(&format!("flag provided but not defined: {}", arg));
                print_usage();
                exit(2);
            }
        }
        i += 1;
    }

    // Accept bare ports on the flag too: -addr 26398 -> 0.0.0.0:26398
    let addr = env::normalize_addr(&addr);

    if let Err(e) = run(&addr, username, password, timeout, verbose) {
        log::error(&format!("server error: {}", e));
        exit(1);
    }
}

fn run(
    addr: &str,
    username: String,
    password: String,
    timeout: Duration,
    verbose: bool,
) -> std::io::Result<()> {
    let cfg = Config {
        username,
        password,
        timeout,
        verbose,
    };

    let listener = TcpListener::bind(addr)?;
    log::info(&format!(
        "proxy-server listening on {} (SOCKS5+HTTP unified)",
        addr
    ));
    if !cfg.username.is_empty() {
        log::info(&format!("auth: ENABLED (user={})", cfg.username));
    } else {
        log::info("auth: DISABLED (public proxy - set -username/-password or PROXY_USERNAME/PROXY_PASSWORD)");
    }
    log::info(&format!(
        "Test SOCKS5:  curl -x socks5h://{}@127.0.0.1:1080 https://example.com",
        cfg.username
    ));
    log::info(&format!(
        "Test HTTP:   curl -x http://{}@127.0.0.1:1080 https://example.com",
        cfg.username
    ));

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let cfg = Config {
                    username: cfg.username.clone(),
                    password: cfg.password.clone(),
                    timeout: cfg.timeout,
                    verbose: cfg.verbose,
                };
                std::thread::spawn(move || handle_conn(s, cfg));
            }
            Err(e) => {
                log::error(&format!("accept error: {}", e));
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Sniff the first byte to decide SOCKS5 vs HTTP on the same port.
/// SOCKS5 always starts with 0x05; HTTP starts with ASCII method letters.
fn handle_conn(stream: std::net::TcpStream, cfg: Config) {
    let mut conn = match Conn::new(stream) {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = conn.set_read_timeout(Some(cfg.timeout));

    let first = match conn.peek_byte() {
        Ok(b) => b,
        Err(_) => return,
    };

    if first == 0x05 {
        socks5::handle_socks5(&mut conn, &cfg);
    } else {
        httpproxy::handle_http(&mut conn, &cfg);
    }
}

/// Parse a Go-style duration string such as `30s`, `500ms`, `1m30s`, `2h`.
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut total = Duration::ZERO;
    let mut saw_any = false;

    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        if start == i {
            return None; // expected a number
        }
        let value: f64 = s[start..i].parse().ok()?;

        let unit_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_digit() && bytes[i] != b'.' {
            i += 1;
        }
        let unit = &s[unit_start..i];

        let nanos = match unit {
            "ns" => value,
            "us" | "µs" | "μs" => value * 1_000.0,
            "ms" => value * 1_000_000.0,
            "s" => value * 1_000_000_000.0,
            "m" => value * 60.0 * 1_000_000_000.0,
            "h" => value * 3600.0 * 1_000_000_000.0,
            "" => value * 1_000_000_000.0, // bare number = seconds
            _ => return None,
        };
        if !nanos.is_finite() || nanos < 0.0 {
            return None;
        }
        total += Duration::from_nanos(nanos as u64);
        saw_any = true;
    }

    if saw_any {
        Some(total)
    } else {
        None
    }
}

fn print_usage() {
    eprintln!(
        "Usage: proxy-server [options]\n  \
         -addr string        Listen address (default 0.0.0.0:1080)\n  \
         -username string    Proxy username (empty = no auth)\n  \
         -password string    Proxy password\n  \
         -timeout duration   Dial / IO timeout (default 30s)\n  \
         -v                  Verbose logging"
    );
}