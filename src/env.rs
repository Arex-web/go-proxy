use std::env;

/// Load a `.env`-style file into the process environment.
///
/// Existing variables win (shell / systemd takes precedence over the file).
/// Supports comments, blank lines, `export KEY=VALUE` and quoted values.
pub fn load_env_file(path: &str) -> bool {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    for raw in content.lines() {
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim();
        }
        let eq = match line.find('=') {
            Some(i) if i > 0 => i,
            _ => continue,
        };
        let key = line[..eq].trim();
        let mut val = line[eq + 1..].trim().to_string();

        let bytes = val.as_bytes();
        if bytes.len() >= 2 {
            let first = bytes[0];
            let last = bytes[bytes.len() - 1];
            if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
                val = val[1..val.len() - 1].to_string();
            }
        }

        if env::var_os(key).is_none() {
            env::set_var(key, val);
        }
    }
    true
}

/// Accept `"26398"` (bare port) -> `"0.0.0.0:26398"`.
/// `":26398"` and `"host:port"` are left as-is.
pub fn normalize_addr(addr: &str) -> String {
    let addr = addr.trim();
    if addr.is_empty() {
        return "0.0.0.0:1080".to_string();
    }
    if addr.contains(':') {
        return addr.to_string();
    }
    format!("0.0.0.0:{}", addr)
}

/// Load config from `.env`-style files.
///
/// Order: `$PROXY_ENV_FILE`, `./.env`, `./proxy.env`, `/etc/proxy-server/proxy.env`.
/// The first file that defines a key wins; later files only fill in gaps.
pub fn load_env() {
    if let Ok(p) = env::var("PROXY_ENV_FILE") {
        if !p.is_empty() {
            load_env_file(&p);
            return;
        }
    }

    for p in [".env", "proxy.env", "/etc/proxy-server/proxy.env"] {
        load_env_file(p);
    }

    // Convenient aliases:
    //   PROXY_PORT=8080 -> PROXY_ADDR=0.0.0.0:8080 (if PROXY_ADDR unset)
    //   PORT=8080       -> PROXY_ADDR=0.0.0.0:8080
    //   PROXY_ADDR=26398 (bare port) -> 0.0.0.0:26398
    if let Ok(p) = env::var("PROXY_ADDR") {
        if !p.is_empty() {
            env::set_var("PROXY_ADDR", normalize_addr(&p));
            return;
        }
    }
    if let Ok(p) = env::var("PROXY_PORT") {
        if !p.is_empty() {
            env::set_var("PROXY_ADDR", format!("0.0.0.0:{}", p.trim()));
            return;
        }
    }
    if let Ok(p) = env::var("PORT") {
        if !p.is_empty() {
            env::set_var("PROXY_ADDR", format!("0.0.0.0:{}", p.trim()));
        }
    }
}