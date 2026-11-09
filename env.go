package main

import (
	"bufio"
	"os"
	"strings"
)

// loadEnvFile loads KEY=VALUE lines into the process env.
// Existing environment variables take precedence (shell / systemd wins over file).
// Supports: comments with #, blank lines, "export KEY=VALUE", quoted values.
func loadEnvFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Allow long lines (passwords etc.)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimSpace(line)
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		// Strip surrounding quotes (single or double)
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
	return true
}

// loadEnv loads config from .env-style files.
// Order: $PROXY_ENV_FILE, ./.env, ./proxy.env, /etc/proxy-server/proxy.env
// First found wins, but later files fill in missing keys (via no-override rule).
func loadEnv() {
	if p := os.Getenv("PROXY_ENV_FILE"); p != "" {
		loadEnvFile(p)
		return
	}
	for _, p := range []string{".env", "proxy.env", "/etc/proxy-server/proxy.env"} {
		loadEnvFile(p)
	}
	// Convenient aliases:
	//   PROXY_PORT=8080  ->  PROXY_ADDR=0.0.0.0:8080 (if addr not set)
	//   PORT=8080        ->  PROXY_PORT=8080
	if os.Getenv("PROXY_ADDR") == "" {
		if p := os.Getenv("PROXY_PORT"); p != "" {
			_ = os.Setenv("PROXY_ADDR", "0.0.0.0:"+p)
		} else if p := os.Getenv("PORT"); p != "" {
			_ = os.Setenv("PROXY_ADDR", "0.0.0.0:"+p)
		}
	}
}
