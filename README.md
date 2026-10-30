# Manew 👀 — interactive Go network diagnostics

A standalone terminal menu with an ASCII banner and nine modules. No third-party Go packages.

## Build

```powershell
go build -o manew.exe .
.\manew.exe
```

Linux/macOS: `go build -o manew . && ./manew`

## Menu

1. **WHOIS/RDAP**: IANA RDAP bootstrap, follows HTTPS redirects and domain-related RDAP referrals, then falls back to WHOIS port 43 and WHOIS referrals. `.et` domains use `https://rdap.ethiotelecom.et/rdap/domain/{domain}` and `whois.ethiotelecom.et:43` directly.
2. **DNS**: A/AAAA, MX, NS, TXT, CNAME records via the system DNS resolver.
3. **IP**: IP resolution and PTR (reverse DNS) records. No IP geolocation database or third-party API.
4. **SSL/TLS**: handshake, TLS version, cipher suite, certificate chain, issuer, SANs and expiry.
5. **HTTP**: HEAD request, status, final URL, basic security headers and latency.
6. **Ports**: bounded TCP connect check for up to 64 user-selected ports with a maximum 10 concurrent attempts. **Only use on infrastructure you own or are authorized to assess.**
7. **Subdomains**: passive certificate transparency enumeration from public `crt.sh` records. Not exhaustive, may include historical names.
8. **Health**: DNS resolution, HTTPS handshake and HTTP reachability snapshot.
9. **Threat**: informational IPv4 DNSBL checks for Spamhaus and SpamCop, mainly useful for mail-server IP reputations. Not a malware verdict. DNSBL access policies may restrict queries, so an absent response is not a clean bill of health.

Select `0` to quit. After each operation the menu appears again. Internet access is required for most checks.

## Details & limits

- WHOIS and RDAP lookups return the most recent successful response, and record attempted servers.
- TLS validation is performed normally (no `InsecureSkipVerify`).
- The URL-based HTTP check makes a HEAD request; sites that do not support HEAD can return 405.
- DNS TXT records can include verification secrets; do not share reports without reviewing them.
- There is no continuous monitoring, CVE search, malware feed integration, or aggressive subdomain brute forcing.
- A filtered port may appear the same as closed.
- Results are rendered as styled plain text in the terminal, not exported to disk. WHOIS records keep their classic `key: value` layout; RDAP objects are summarised as a registrar-style block.
- The app paints a near-black canvas and a mint-to-violet accent palette, similar to a modern TUI. Set `NO_COLOR=1` to disable escapes (piped output is plain text automatically).

## Tests

`go test ./...`

## Releases

Push a tag such as `v1.0.0` (or run the **release** workflow manually) and GitHub Actions publishes:

- `manew-windows-amd64.exe` / `manew-windows-arm64.exe`
- `manew-linux-amd64` / `manew-linux-arm64`

The binaries are statically built with `CGO_ENABLED=0`, so the Linux builds run on any modern distribution.

## License

MIT — see [LICENSE](LICENSE).
