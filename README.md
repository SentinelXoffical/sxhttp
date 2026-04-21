# ⚡ SentinelX — WebVulnerity Scanner

Enterprise-grade Go web vulnerability scanner with concurrent crawling and multi-method SQLi detection.

## Features

| Feature | Details |
|---------|---------|
| **Crawler** | Concurrent BFS crawler, HTML parser, form extraction |
| **WAF Detection** | Fingerprints 10+ WAFs (Cloudflare, Akamai, Imperva, ModSecurity...) |
| **SQLi Detection** | Error-based, Boolean-blind, Time-based |
| **Tamper Scripts** | 11 WAF bypass techniques |
| **Auth Handler** | Auto-detects login form, CSRF tokens, captures session cookie |
| **Rate Limiter** | Token-bucket RPS + min-delay |
| **Rich Reports** | Terminal summary + JSON + HTML dark-mode + TXT |
| **Proxy Support** | HTTP/SOCKS5 proxy support |
| **Exit Codes** | 0=clean, 1=error, 2=vulns (CI/CD friendly) |

## Build

```bash
# Requires Go 1.21+
chmod +x build.sh && ./build.sh
```

## Usage

```bash
# Basic scan
./sentinelx -u https://target.com

# Full scan - 8 threads, depth 4, all formats
./sentinelx -u https://target.com -t 8 -d 4 --risk 2 --format all -o report

# WAF bypass with tamper scripts
./sentinelx -u https://target.com --tamper space2comment,randomcase,inlinecomment

# Through Burp proxy
./sentinelx -u https://target.com --proxy http://127.0.0.1:8080 --no-waf

# Auth (auto-detect login form)
./sentinelx -u https://target.com/app \
  --auth-url https://target.com/login \
  --auth-user admin --auth-pass secret

# Skip crawl, test URL params only
./sentinelx -u "https://target.com/page?id=1" --no-crawl

# With scope restriction
./sentinelx -u https://target.com --scope https://target.com/app/

# List tamper scripts
./sentinelx --list-tampers
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-u` | — | Target URL (required) |
| `-t` | 4 | Threads |
| `-d` | 3 | Crawl depth |
| `--max-pages` | 200 | Max pages |
| `--risk` | 1 | Risk level 1-3 |
| `--sleep` | 5 | Sleep sec for time-based |
| `--rps` | 10 | Requests per second |
| `--delay` | 100 | Min delay ms |
| `-o` | sentinelx_report | Output file |
| `--format` | all | json/html/txt/all |
| `--proxy` | — | HTTP proxy |
| `--cookie` | — | Cookie header |
| `--ua` | — | User-Agent |
| `--tamper` | — | Tamper scripts (comma-sep) |
| `--no-crawl` | false | Skip crawl |
| `--no-waf` | false | Skip WAF detection |
| `--scope` | — | URL prefix scope |
| `--auth-url` | — | Login URL |
| `--auth-user` | — | Username |
| `--auth-pass` | — | Password |
| `--log-level` | info | debug/info/warn/error |
| `--log-file` | — | Save log to file |
| `--list-tampers` | — | List tamper scripts |

## Tamper Scripts

`space2comment`, `space2plus`, `space2dash`, `randomcase`, `uppercase`, `urlencode`, `doubleurlencode`, `hexstrings`, `inlinecomment`, `plus2concat`, `nullbyte`

## Exit Codes

- `0` — Clean
- `1` — Error  
- `2` — Vulnerabilities found

---
**For authorized bug bounty / penetration testing only.**
