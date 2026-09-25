# Proxy Formats

The parser (`src/parser.js`) accepts one proxy per line and auto-detects the format. Input is normalized before checking: whitespace trimmed, inline `# comments` stripped, empty lines ignored, duplicates removed (counted, not silently dropped), malformed lines reported with line numbers and reasons.

## Recognized formats

| Format | Example |
| --- | --- |
| `IP:PORT` | `1.2.3.4:8080` |
| `IP:PORT:USERNAME:PASSWORD` | `1.2.3.4:8080:alice:s3cret` |
| `USERNAME:PASSWORD@IP:PORT` | `alice:s3cret@1.2.3.4:8080` |
| `http://IP:PORT` | `http://1.2.3.4:8080` |
| `https://IP:PORT` | `https://1.2.3.4:8443` |
| `socks4://IP:PORT` | `socks4://1.2.3.4:1080` |
| `socks4a://IP:PORT` | `socks4a://1.2.3.4:1080` |
| `socks5://IP:PORT` | `socks5://1.2.3.4:1080` |
| `scheme://USER:PASS@IP:PORT` | `socks5://alice:s3cret@1.2.3.4:1080` |
| Hostname instead of IP | `proxy.example.com:3128` |
| Bracketed IPv6 | `[2001:db8::1]:8080`, `socks5://[fe80::1]:1080` |

Passwords may contain `:` in the `IP:PORT:USER:PASS` form — everything after the third colon is treated as the password.

## IPv6 notes

- Bracketed IPv6 (`[…]:port`) is the recommended, always-supported form.
- Unbracketed IPv6 is accepted only when the address portion is unambiguously parseable (e.g. `2001:db8::1:8080`); ambiguous forms must use brackets.
- IPv6 zone indices (`fe80::1%eth0`) are rejected — they are not meaningful for remote proxies.

## Validation rules

- **IPv4** — strict dotted-quad, octets 0–255, no leading zeros (`010.0.0.1` rejected as ambiguous). All-numeric dotted strings must be valid IPv4 — `1.2.3.256` and `1.2.3.4.5` are rejected rather than being treated as odd hostnames.
- **Hostname** — RFC-style labels (letters, digits, `-`, `_`), max 253 chars.
- **Port** — integer 1–65535.
- **Credentials** — no whitespace; empty username rejected.

## Junk-tolerant rescue

Lists copied from chats, emails or web pages often get mangled by rich-text editors. ProxyCheck extracts the proxy when a line fails the strict parse but contains exactly one recognizable endpoint:

```text
user:[pass@host:port](mailto:pass@host:port)   → user:pass@host:port   (markdown/mailto links)
<1.2.3.4:8080>  "1.2.3.4:8080"  proxy=1.2.3.4:8080.                    (wrappers/quotes/trailing punctuation)
1.2.3.4:8080,5.6.7.8:3128;9.9.9.9:1080                                  (comma/semicolon separated lists)
```

Lines containing two distinct endpoints stay invalid (reported), and strict-only failures (like `1.2.3.4.5:8080`) are never silently "fixed".

## Rejected input (reported, not fatal)

```text
not a proxy          → missing port / invalid host
1.2.3.4              → missing port
1.2.3.4:99999        → invalid port
ftp://1.2.3.4:21     → unsupported protocol "ftp"
1.2.3.4:8080:a:b:c:d → see rules above (password = "b:c:d")
user@:8080           → invalid host
```

Every invalid line is returned with its line number and reason (first 100 shown in the UI/API), so nothing silently disappears.

## Deduplication

Duplicates are detected after normalization on the identity
`protocol | host | port | username | password` — so the same endpoint with different requested protocols or credentials remains distinct. The summary reports:

```text
Input: 5,000
Duplicates removed: 743
Unique proxies: 4,257
```

## Credential masking

Wherever proxies are displayed or exported by default, credentials are masked:

```text
user:********@1.2.3.4:8080
```

Passwords never leave the server in results, logs or exports unless you explicitly request a credential-preserving export (`include=credentials&confirm=yes`).
