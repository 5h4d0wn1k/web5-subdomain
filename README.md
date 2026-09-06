# WEB5 — Subdomain Scanner

DNS enumeration and subdomain discovery with wildcard detection and HTTP probing.

## Overview

This project implements a subdomain enumeration tool that:
- Resolves DNS records for subdomain candidates
- Detects and filters wildcard DNS entries
- Probes discovered subdomains with HTTP/HTTPS
- Extracts page titles from responses
- Uses concurrent DNS lookups for fast scanning

## Features

- **DNS enumeration**: Resolve subdomains via system DNS
- **Wildcard detection**: Automatically detect and filter wildcard DNS
- **HTTP probing**: Check HTTP and HTTPS on discovered subdomains
- **Title extraction**: Grab page titles from responses
- **Thread pool**: Configurable concurrency with concurrent.futures
- **Custom wordlists**: Load your own subdomain lists
- **Built-in wordlist**: 200+ common subdomain prefixes

## Installation

```bash
# No external dependencies required — uses Python stdlib only
python3 --version  # Requires Python 3.7+
```

## Usage

```bash
# Offline demo: scans a simulated DNS zone with wildcard DNS (exit 0)
python3 subdomain.py --demo

# Basic scan (lab-only targets, e.g. example.com in your own domain space)
python3 subdomain.py example.com

# With custom wordlist
python3 subdomain.py example.com -w subdomains.txt

# With more threads
python3 subdomain.py example.com -t 50

# Skip HTTP probing (DNS only)
python3 subdomain.py example.com --no-http

# Export findings to JSON
python3 subdomain.py example.com -o findings/subs.json -v
```

## CLI Options

| Option | Description |
|--------|-------------|
| `domain` | Target domain (e.g. example.com) |
| `-w, --wordlist` | Path to subdomain wordlist file |
| `-t, --threads` | Number of threads (default: 10) |
| `--dns-timeout` | DNS resolution timeout in seconds |
| `--http-timeout` | HTTP probe timeout in seconds |
| `--no-http` | Disable HTTP/HTTPS probing |
| `-o, --output` | Export results to a JSON file |
| `-v, --verbose` | Verbose output |
| `--demo` | Offline demo against a simulated DNS zone + localhost app |

## Example Output

```
============================================================
  WEB5 — Subdomain Scanner
============================================================
  Domain:    example.com
  Threads:   10
  Wordlist:  200 entries
  HTTP Probe: True
============================================================

[*] Detecting wildcard DNS...
[*] No wildcard DNS detected

[*] Scanning 200 subdomains...

  [+] mail.example.com                 192.168.1.10         
  [+] www.example.com                  192.168.1.1          [HTTP:200] [HTTPS:200]
  [+] api.example.com                  192.168.1.20         [HTTP:200] [HTTPS:200]
  [+] vpn.example.com                  192.168.1.30         

============================================================
  Scan Complete
============================================================
  Time:       12.34s
  DNS Queries: 200
  Found:      4
  Wildcards:  0
  HTTP Probed: 4
  Errors:     3
============================================================
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## Running the Demo and Tests

`subdomain.py --demo` runs the full scan path against a simulated DNS zone:

- **Vulnerable zone** (`lab.test`): `www`, `api`, `dev` resolve to `127.0.0.1`
  (HTTP 200 with vhost titles); any other label hits a wildcard IP (`192.0.2.10`).
- **Wildcard detection** confirms the wildcard, then random/unknown labels are
  filtered out, leaving exactly the three planted subdomains.

```bash
python3 -m unittest discover -s tests -v
```

## Live Lab Test Plan

Test only against domains you control (e.g. a subdomain you hold, or `*.test.local`
on your own DNS server):

1. Deploy a local DNS server on 127.0.0.1 with a small set of planted records and an
   optional wildcard entry.
2. Baseline: `python3 subdomain.py test.local -v`
3. Confirm discovered subdomains match the planted records.
4. Enable wildcard DNS and confirm unknown labels are filtered (no false positives).
5. Point the scanner at a zone with no subdomains and confirm zero findings.
6. Document the zone configuration and evidence in your lab report.

## Metrics

- **Video metric**: 60-second screencast of `python3 subdomain.py --demo` (planted
  `www/api/dev` found, wildcard labels filtered, exit 0) and
  `python3 -m unittest discover -s tests -v`, recorded against the lab-only targets.
- **Pass rate**: all unit tests green; demo exit 0.

## License

MIT
