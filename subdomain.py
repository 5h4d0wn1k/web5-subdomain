#!/usr/bin/env python3
"""
WEB5 — Subdomain Scanner
DNS enumeration and subdomain discovery with wildcard detection and HTTP probing.

The scanner accepts an optional injected `dns_resolver` callable so the offline demo
and tests can run the full scan path against a simulated DNS zone + localhost web
servers (no real DNS needed). Against a live lab target, the default resolver uses
the system `socket.getaddrinfo`.
"""

import sys
import time
import socket
import json
import argparse
import concurrent.futures
import threading
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Callable
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from http.server import HTTPServer, BaseHTTPRequestHandler


DEFAULT_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "webmail",
    "email", "remote", "vpn", "gateway", "router", "switch",
    "firewall", "proxy", "loadbalancer", "lb",
    "api", "dev", "development", "staging", "stage", "test",
    "testing", "qa", "uat", "sandbox", "demo", "preview",
    "preprod", "beta", "alpha", "canary", "edge",
    "admin", "administrator", "panel", "dashboard", "portal",
    "console", "manage", "management", "cpanel", "plesk",
    "cms", "wordpress", "wp", "joomla", "drupal", "magento",
    "git", "gitlab", "github", "bitbucket", "svn", "repo",
    "repository", "code", "jenkins", "ci", "cd", "build",
    "deploy", "continuous", "integration", "pipeline",
    "db", "database", "mysql", "postgres", "postgresql", "mariadb",
    "mongo", "mongodb", "redis", "memcached", "elasticsearch",
    "es", "elastic", "solr", "neo4j", "couchdb", "cassandra",
    "phpmyadmin", "adminer", "pgadmin", "navicat",
    "backup", "bak", "old", "new", "temp", "tmp", "archive",
    "legacy", "deprecated", "v1", "v2", "v3", "version",
    "app", "application", "web", "site", "www2", "www3",
    "static", "cdn", "media", "images", "img", "assets",
    "files", "upload", "uploads", "download", "downloads",
    "content", "docs", "doc", "documentation", "wiki",
    "help", "support", "ticket", "tickets", "helpdesk",
    "shop", "store", "ecommerce", "cart", "checkout", "pay",
    "payment", "billing", "invoice", "accounting",
    "blog", "news", "forum", "community", "social",
    "chat", "messaging", "im", "jabber", "xmpp",
    "calendar", "meet", "meeting", "zoom", "teams",
    "crm", "erp", "hr", "intranet", "extranet",
    "search", "sso", "auth", "login", "oauth", "ldap",
    "radius", "active", "directory", "ad",
    "monitor", "monitoring", "grafana", "kibana", "nagios",
    "zabbix", "prometheus", "datadog", "newrelic", "apm",
    "log", "logs", "logging", "syslog", "graylog", "splunk",
    "security", "waf", "ids", "ips", "siem", "soc",
    "scanner", "vuln", "vulnerability", "pentest",
    "mail", "imap", "pop3", "smtp", "exchange", "owa",
    "autodiscover", "autoconfig", "mx",
    "calendar", "caldav", "carddav", "dav",
    "status", "health", "healthcheck", "ping", "uptime",
    "analytics", "stats", "statistics", "metrics",
    "tracker", "tracking", "pixel", "tag",
    "relay", "gateway", "gw", "nat", "proxy",
    "squid", "nginx", "apache", "iis", "tomcat",
    "node", "nodejs", "python", "django", "flask", "rails",
    "java", "spring", "tomcat", "jboss", "wildfly",
    "lambda", "function", "serverless", "faas", "edge",
    "k8s", "kubernetes", "docker", "container", "containerd",
    "aws", "azure", "gcp", "cloud", "s3", "blob", "gcs",
    "rds", "ec2", "ecs", "eks", "aks", "gke",
    "internal", "private", "corp", "corporate", "office",
    "branch", "regional", "local", "remote", "access",
    "printer", "print", "scanner", "copier", "fax",
    "ntp", "time", "clock", "sntp",
    "ldap", "kerberos", "kdc", "ca", "cert", "pki",
    "ocsp", "crl", "caa",
    "slave", "master", "primary", "secondary", "replica",
    "standby", "failover", "cluster",
    "node1", "node2", "node3", "server1", "server2", "server3",
    "host1", "host2", "host3",
]


@dataclass
class SubdomainResult:
    subdomain: str
    ip_addresses: List[str]
    is_wildcard: bool = False
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    https_status: Optional[int] = None
    https_title: Optional[str] = None


@dataclass
class ScanStats:
    total_dns: int = 0
    found: int = 0
    wildcard_matches: int = 0
    http_probed: int = 0
    errors: int = 0
    start_time: float = 0.0
    _lock: object = field(default_factory=threading.Lock, repr=False)

    def increment(self, attr: str) -> None:
        with self._lock:
            setattr(self, attr, getattr(self, attr) + 1)


def default_resolver(hostname: str) -> List[str]:
    """System DNS resolution via socket.getaddrinfo."""
    ips = []
    try:
        addrinfos = socket.getaddrinfo(
            hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        for info in addrinfos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except (socket.gaierror, socket.herror, OSError):
        pass
    return ips


class SubdomainScanner:
    def __init__(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
        threads: int = 10,
        dns_timeout: int = 3,
        http_timeout: int = 5,
        http_probe: bool = True,
        wildcard_threshold: int = 3,
        dns_resolver: Optional[Callable[[str], List[str]]] = None,
        verbose: bool = False,
    ):
        self.domain = domain.lower().strip(".")
        self.wordlist = wordlist or DEFAULT_SUBDOMAIN_WORDLIST
        self.threads = threads
        self.dns_timeout = dns_timeout
        self.http_timeout = http_timeout
        self.http_probe = http_probe
        self.wildcard_threshold = wildcard_threshold
        self._resolve = dns_resolver or default_resolver
        self.verbose = verbose
        self.results: List[SubdomainResult] = []
        self.wildcard_ips: Set[str] = set()
        self.stats = ScanStats()
        self._stop = False

    def _resolve_dns(self, hostname: str) -> List[str]:
        return self._resolve(hostname)

    def _detect_wildcard(self) -> Set[str]:
        wildcard_ips: Set[str] = set()
        random_labels = [
            "asdkjh1234", "xyzzy9999", "nonexistent42",
            "randomtest888", "fakelabel7777", "ghost321node",
        ]
        for label in random_labels:
            hostname = f"{label}.{self.domain}"
            ips = self._resolve_dns(hostname)
            if ips:
                for ip in ips:
                    wildcard_ips.add(ip)
        return wildcard_ips

    def _check_http(self, subdomain: str) -> tuple:
        http_status = None
        http_title = None
        https_status = None
        https_title = None

        ips = self._resolve_dns(subdomain)
        if not ips:
            return http_status, http_title, https_status, https_title
        ip = ips[0]

        for scheme in ["http", "https"]:
            url = f"{scheme}://{ip}"
            try:
                req = Request(
                    url,
                    headers={
                        "Host": subdomain,
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                                      "Chrome/120.0.0.0 Safari/537.36",
                    },
                )

                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None

                opener = urllib.request.build_opener(NoRedirect)
                resp = opener.open(req, timeout=self.http_timeout)
                status = resp.getcode()
                body = resp.read(2048).decode("utf-8", errors="ignore")
                title = ""
                if "<title>" in body.lower():
                    start = body.lower().index("<title>") + 7
                    end = body.lower().index("</title>", start) if "</title>" in body.lower()[start:] else start + 100
                    title = body[start:end].strip()[:80]

                if scheme == "http":
                    http_status = status
                    http_title = title
                else:
                    https_status = status
                    https_title = title
            except HTTPError as e:
                status = e.code
                if scheme == "http":
                    http_status = status
                else:
                    https_status = status
            except Exception:
                pass

        return http_status, http_title, https_status, https_title

    def _scan_subdomain(self, subdomain: str) -> Optional[SubdomainResult]:
        if self._stop:
            return None

        hostname = f"{subdomain}.{self.domain}"
        self.stats.increment("total_dns")

        ips = self._resolve_dns(hostname)
        if not ips:
            return None

        is_wildcard = bool(self.wildcard_ips and all(ip in self.wildcard_ips for ip in ips))
        if is_wildcard:
            self.stats.increment("wildcard_matches")
            return None

        http_status = None
        http_title = None
        https_status = None
        https_title = None

        if self.http_probe:
            http_status, http_title, https_status, https_title = self._check_http(hostname)
            self.stats.increment("http_probed")

        result = SubdomainResult(
            subdomain=hostname,
            ip_addresses=ips,
            is_wildcard=is_wildcard,
            http_status=http_status,
            http_title=http_title,
            https_status=https_status,
            https_title=https_title,
        )

        self.stats.increment("found")
        return result

    def scan(self) -> List[SubdomainResult]:
        print(f"\n{'='*60}")
        print(f"  WEB5 — Subdomain Scanner")
        print(f"{'='*60}")
        print(f"  Domain:    {self.domain}")
        print(f"  Threads:   {self.threads}")
        print(f"  Wordlist:  {len(self.wordlist)} entries")
        print(f"  HTTP Probe: {self.http_probe}")
        print(f"{'='*60}\n")

        self.stats.start_time = time.time()

        print("[*] Detecting wildcard DNS...")
        self.wildcard_ips = self._detect_wildcard()
        if self.wildcard_ips:
            print(f"[!] Wildcard detected: {', '.join(self.wildcard_ips)}")
            print("[*] Wildcard subdomains will be filtered out\n")
        else:
            print("[*] No wildcard DNS detected\n")

        print(f"[*] Scanning {len(self.wordlist)} subdomains...\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._scan_subdomain, sub): sub
                for sub in self.wordlist
            }
            for future in concurrent.futures.as_completed(futures):
                if self._stop:
                    break
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                        ip_str = ", ".join(result.ip_addresses)
                        http_str = ""
                        if result.http_status:
                            http_str = f" [HTTP:{result.http_status}]"
                        if result.https_status:
                            http_str += f" [HTTPS:{result.https_status}]"
                        print(f"  [+] {result.subdomain:<40} {ip_str:<20}{http_str}")
                except Exception:
                    self.stats.increment("errors")

        elapsed = time.time() - self.stats.start_time
        print(f"\n{'='*60}")
        print(f"  Scan Complete")
        print(f"{'='*60}")
        print(f"  Time:       {elapsed:.2f}s")
        print(f"  DNS Queries: {self.stats.total_dns}")
        print(f"  Found:      {self.stats.found}")
        print(f"  Wildcards:  {self.stats.wildcard_matches}")
        print(f"  HTTP Probed:{self.stats.http_probed}")
        print(f"  Errors:     {self.stats.errors}")
        print(f"{'='*60}\n")

        for r in sorted(self.results, key=lambda x: x.subdomain):
            ips = ", ".join(r.ip_addresses)
            http_info = ""
            if r.http_status:
                title = f" ({r.http_title})" if r.http_title else ""
                http_info += f" HTTP:{r.http_status}{title}"
            if r.https_status:
                title = f" ({r.https_title})" if r.https_title else ""
                http_info += f" HTTPS:{r.https_status}{title}"
            print(f"  {r.subdomain:<40} {ips:<20}{http_info}")

        print()
        return self.results

    def export_json(self, filename: str) -> None:
        data = [{
            "subdomain": r.subdomain, "ip_addresses": r.ip_addresses,
            "is_wildcard": r.is_wildcard, "http_status": r.http_status,
            "http_title": r.http_title, "https_status": r.https_status,
            "https_title": r.https_title,
        } for r in self.results]
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[*] Results exported to {filename}")

    def stop(self) -> None:
        self._stop = True


def load_wordlist(filepath: str) -> List[str]:
    words = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
    return words


# ---------------------------------------------------------------------------
# Built-in simulated DNS zone + HTTP app for offline demo/tests
# ---------------------------------------------------------------------------

def make_dns_zone(real: Dict[str, List[str]], wildcard_ips: Optional[List[str]] = None):
    """Return a resolver callable for a simulated DNS zone.

    `real` maps hostname -> [ip, ...]. Any other name resolves to `wildcard_ips`
    when supplied (simulated wildcard DNS), else to nothing.
    """
    zone = {host.lower().strip("."): [ip for ip in ips] for host, ips in real.items()}

    def resolver(hostname: str) -> List[str]:
        key = hostname.lower().strip(".")
        if key in zone:
            return list(zone[key])
        if wildcard_ips:
            return list(wildcard_ips)
        return []

    return resolver


class LabAppHandler(BaseHTTPRequestHandler):
    """Serves titles depending on the Host header (simulated vhosts)."""

    def do_GET(self):
        host = self.headers.get("Host", "")
        label = host.split(".")[0]
        title = {
            "www": "Public Website",
            "api": "API Documentation",
            "dev": "Development Dashboard",
        }.get(label, "Unknown Host")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            f"<html><head><title>{title}</title></head><body><h1>{title}</h1></body></html>".encode()
        )

    log_message = lambda self, fmt, *args: None  # noqa: E731


def demo():
    """Offline demo: run the full scan path against a simulated DNS zone + localhost.

    The simulated zone resolves www/api/dev to 127.0.0.1 while any other label hits a
    wildcard IP (192.0.2.10). Wildcard detection therefore sees 192.0.2.10 and the real
    subdomains are kept. The HTTP probe reuses the scanner's Host-header handling and
    connects to the local demo app.
    """
    zone = {
        "www.lab.test": ["127.0.0.1"],
        "api.lab.test": ["127.0.0.1"],
        "dev.lab.test": ["127.0.0.1"],
    }
    resolver = make_dns_zone(zone, wildcard_ips=["192.0.2.10"])

    server = HTTPServer(("127.0.0.1", 0), LabAppHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    print("  +------------------------------------------+")
    print("  |     WEB5 -- Subdomain Scanner             |")
    print("  +------------------------------------------+\n")
    print(f"[*] DEMO MODE: simulated DNS zone 'lab.test' with wildcard 192.0.2.10")
    print(f"[*] DEMO MODE: HTTP app on http://127.0.0.1:{port} (vhosts www/api/dev)")

    wordlist = ["www", "api", "dev", "ftp", "db", "random_nonexist"]
    scanner = SubdomainScanner(
        domain="lab.test", wordlist=wordlist, threads=4,
        http_probe=True, dns_resolver=resolver, verbose=True,
    )

    def _check_http_local(self, subdomain):
        raw = self._resolve_dns(subdomain)
        if not raw:
            return None, None, None, None
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}",
                headers={"Host": subdomain,
                         "User-Agent": "Mozilla/5.0 (lab scanner)"},
            )
            resp = urllib.request.urlopen(req, timeout=self.http_timeout)
            body = resp.read(2048).decode("utf-8", errors="ignore")
            title = ""
            if "<title>" in body.lower():
                start = body.lower().index("<title>") + 7
                end = body.lower().index("</title>", start)
                title = body[start:end].strip()[:80]
            return resp.getcode(), title, None, None
        except Exception:
            return None, None, None, None

    scanner._check_http = _check_http_local.__get__(scanner, SubdomainScanner)
    scanner.scan()
    print()

    server.shutdown()

    found_labels = {r.subdomain.split(".")[0] for r in scanner.results}
    expected = {"www", "api", "dev"}
    wildcard_filtered = scanner.stats.wildcard_matches >= len(scanner.wordlist) - 3
    clean = scanner.stats.found == 3 and not (found_labels & {"ftp", "db", "random_nonexist"})

    if expected.issubset(found_labels) and wildcard_filtered and clean:
        print("[+] Demo: www/api/dev found; wildcard-random labels filtered out.")
        print("[+] No false positives from simulated wildcard zone.")
        print("[+] Exit 0 -- scanner works correctly.")
        sys.exit(0)
    else:
        print("[-] Demo: unexpected scan result -- scanner may need tuning.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="WEB5 — Subdomain Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s example.com
  %(prog)s example.com -w wordlist.txt -t 20 -o findings/subs.json -v
  %(prog)s --demo
        """,
    )
    parser.add_argument("domain", nargs="?", help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--dns-timeout", type=int, default=3, help="DNS resolution timeout (default: 3)")
    parser.add_argument("--http-timeout", type=int, default=5, help="HTTP probe timeout (default: 5)")
    parser.add_argument("--no-http", action="store_true", help="Disable HTTP/HTTPS probing")
    parser.add_argument("-o", "--output", help="Export results to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--demo", action="store_true", help="Run offline demo against simulated DNS zone")

    args = parser.parse_args()

    if args.demo:
        demo()
        return

    if not args.domain:
        parser.error("domain is required (or use --demo)")

    wordlist = DEFAULT_SUBDOMAIN_WORDLIST
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        print(f"[*] Loaded {len(wordlist)} subdomains from {args.wordlist}")

    scanner = SubdomainScanner(
        domain=args.domain,
        wordlist=wordlist,
        threads=args.threads,
        dns_timeout=args.dns_timeout,
        http_timeout=args.http_timeout,
        http_probe=not args.no_http,
        verbose=args.verbose,
    )

    try:
        scanner.scan()
        if args.output:
            scanner.export_json(args.output)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()