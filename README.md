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
# Basic scan
python3 subdomain.py example.com

# With custom wordlist
python3 subdomain.py example.com -w subdomains.txt

# With more threads
python3 subdomain.py example.com -t 50

# Skip HTTP probing (DNS only)
python3 subdomain.py example.com --no-http

# Custom timeouts
python3 subdomain.py example.com --dns-timeout 5 --http-timeout 10
```

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

## License

MIT
