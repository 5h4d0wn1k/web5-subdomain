import sys
import os
import unittest
import subprocess
from http.server import HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_module():
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "subdomain.py")
    spec = importlib.util.spec_from_file_location("subdomain", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


subdomain = load_module()


class TestWildcardDetection(unittest.TestCase):
    def test_wildcard_detected_with_zone(self):
        resolver = subdomain.make_dns_zone(
            {"www.lab.test": ["127.0.0.1"]}, wildcard_ips=["192.0.2.10"]
        )
        scanner = subdomain.SubdomainScanner(
            domain="lab.test", wordlist=["www"], threads=2,
            http_probe=False, dns_resolver=resolver,
        )
        wildcards = scanner._detect_wildcard()
        self.assertIn("192.0.2.10", wildcards)

    def test_no_wildcard_on_clean_zone(self):
        resolver = subdomain.make_dns_zone({"www.lab.test": ["127.0.0.1"]})
        scanner = subdomain.SubdomainScanner(
            domain="lab.test", wordlist=["www"], threads=2,
            http_probe=False, dns_resolver=resolver,
        )
        wildcards = scanner._detect_wildcard()
        self.assertEqual(wildcards, set())


class TestScanVulnerableSimulator(unittest.TestCase):
    def test_planted_subdomains_found_and_wildcard_filtered(self):
        resolver = subdomain.make_dns_zone(
            {
                "www.lab.test": ["127.0.0.1"],
                "api.lab.test": ["127.0.0.1"],
                "dev.lab.test": ["127.0.0.1"],
            },
            wildcard_ips=["192.0.2.10"],
        )
        scanner = subdomain.SubdomainScanner(
            domain="lab.test",
            wordlist=["www", "api", "dev", "ftp", "db"],
            threads=4,
            http_probe=False,
            dns_resolver=resolver,
        )
        results = scanner.scan()
        found = {r.subdomain for r in results}
        self.assertEqual(found, {"www.lab.test", "api.lab.test", "dev.lab.test"})
        self.assertEqual(scanner.stats.wildcard_matches, 2)


class TestScanCleanControl(unittest.TestCase):
    def test_no_false_positives(self):
        resolver = subdomain.make_dns_zone({})
        scanner = subdomain.SubdomainScanner(
            domain="lab.test",
            wordlist=["www", "api", "dev", "ftp", "db"],
            threads=4,
            http_probe=False,
            dns_resolver=resolver,
        )
        results = scanner.scan()
        self.assertEqual(results, [])


class TestDemoAndCLI(unittest.TestCase):
    def test_demo_exit_zero(self):
        r = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "subdomain.py"), "--demo"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("www.lab.test", r.stdout)

    def test_target_required(self):
        r = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "subdomain.py")],
            capture_output=True, text=True, timeout=30,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("usage", r.stderr.lower())


class TestHttpProbing(unittest.TestCase):
    def test_http_probe_against_localhost(self):
        import threading
        server = HTTPServer(("127.0.0.1", 0), subdomain.LabAppHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            titles = {}
            scanner = subdomain.SubdomainScanner(
                domain="lab.test", wordlist=["www"], http_probe=True,
                dns_resolver=lambda h: ["127.0.0.1"],
            )

            def probe(host):
                import urllib.request
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}", headers={"Host": host},
                )
                resp = urllib.request.urlopen(req, timeout=3)
                body = resp.read(2048).decode("utf-8", errors="ignore")
                if "<title>" in body.lower():
                    start = body.lower().index("<title>") + 7
                    end = body.lower().index("</title>", start)
                    titles[host.split(".")[0]] = body[start:end].strip()[:80]
                resp.close()

            probe("www.lab.test")
            probe("api.lab.test")
            probe("dev.lab.test")
        finally:
            server.shutdown()
        self.assertEqual(titles.get("www"), "Public Website")
        self.assertEqual(titles.get("api"), "API Documentation")
        self.assertEqual(titles.get("dev"), "Development Dashboard")


if __name__ == "__main__":
    unittest.main()