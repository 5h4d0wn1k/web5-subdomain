> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# WEB5 — Subdomain Scanner

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/web5-subdomain)
![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/web5-subdomain)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/web5-subdomain)

Python **subdomain enumeration and DNS recon** tool with wildcard-DNS detection, concurrent resolution, and HTTP/HTTPS probing with page-title extraction — built on the standard library only.

## Why

Subdomain discovery is the first step of any authorized **web reconnaissance** and asset-inventory exercise: hidden services, dev portals, and VPN endpoints often live on forgotten subdomains. WEB5 automates name resolution, flags **wildcard DNS** (a common source of false positives), and probes discovered hosts over HTTP(S) to fingerprint credentials-only portals and takeover candidates. It is purpose-built for **authorized security testing, OSINT collection on domains you own, and academic study** — entirely offline demo included, so you can profile the full scan path without touching any real infrastructure.

## Features

- **DNS enumeration** — resolves subdomain candidates via system DNS (`concurrent.futures` thread pool).
- **Wildcard detection** — automatically detects and filters wildcard DNS entries to avoid false positives.
- **HTTP probing** — checks HTTP and HTTPS on discovered subdomains with timeout control.
- **Title extraction** — grabs page titles from HTTP responses.
- **Configurable concurrency** — `-t/--threads`, `--dns-timeout`, `--http-timeout`.
- **Custom wordlists** — any file of prefixes; built-in default of 200+ common prefixes.
- **JSON export** — `-o findings.json` for pipeline integration.

## Quickstart

```bash
# Offline demo (simulated DNS zone with wildcard), exit 0
python3 subdomain.py --demo

# Basic scan of a domain you own
python3 subdomain.py example.com

# Custom wordlist + more threads
python3 subdomain.py example.com -w subdomains.txt -t 50

# DNS-only (skip HTTP probing), export JSON
python3 subdomain.py example.com --no-http -o findings/subs.json -v
```

```bash
# Run the offline unit tests
python3 -m unittest discover -s tests -v
```

## Project structure

```
web5-subdomain/
├── subdomain.py    # main scanner CLI (stdlib only, Python 3.7+)
├── tests/          # offline unittest suite (7 tests)
└── ETHICS.md, SCOPE.md  # authorized-use rules
```

## Documentation

- [ETHICS.md](ETHICS.md) — authorized-use policy
- [SCOPE.md](SCOPE.md) — scan scope
- [SECURITY.md](SECURITY.md) — security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Scan only systems you own or are authorized to assess.

## License

MIT. See [LICENSE](LICENSE).