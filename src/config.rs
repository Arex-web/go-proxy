use std::time::Duration;

pub struct Config {
    pub username: String,
    pub password: String,
    pub timeout: Duration,
    pub verbose: bool,
}

impl Config {
    pub fn auth_enabled(&self) -> bool {
        !self.username.is_empty()
    }

    /// RFC 1929 user/pass check with a constant-time comparison.
    pub fn check_socks5_auth(&self, user: &[u8], pass: &[u8]) -> bool {
        if !self.auth_enabled() {
            return true;
        }
        constant_time_eq(user, self.username.as_bytes())
            && constant_time_eq(pass, self.password.as_bytes())
    }

    /// Verify `Proxy-Authorization: Basic <base64(user:pass)>`.
    pub fn check_http_auth(&self, header_val: &str) -> bool {
        if !self.auth_enabled() {
            return true;
        }
        let encoded = match header_val.strip_prefix("Basic ") {
            Some(v) => v.trim(),
            None => return false,
        };
        let decoded = match base64_decode(encoded) {
            Some(d) => d,
            None => return false,
        };
        let mut parts = decoded.splitn(2, |b| *b == b':');
        let user = parts.next().unwrap_or(b"");
        let pass = match parts.next() {
            Some(p) => p,
            None => return false,
        };
        self.check_socks5_auth(user, pass)
    }
}

/// Length-independent constant-time-ish comparison (mirrors Go's `subtle.ConstantTimeCompare`).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Standard base64 (with padding) decoder.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        } as u32;

        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            if bits > 0 {
                buf &= (1 << bits) - 1;
            } else {
                buf = 0;
            }
        }
    }
    Some(out)
}