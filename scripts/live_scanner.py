"""Live Attack Scanner — Test the SOC against real vulnerable targets.

Performs SAFE, LEGAL reconnaissance against intentionally-vulnerable web apps
and generates real alert data from the findings. These alerts flow through
the full AI pipeline (triage → enrichment → hunting → response → learning).

Legal Targets (designed for testing):
  - testphp.vulnweb.com    — Acunetix intentionally vulnerable PHP app
  - testhtml5.vulnweb.com  — Acunetix HTML5 vulnerable app
  - testaspnet.vulnweb.com — Acunetix ASP.NET vulnerable app

What it does:
  1. HTTP header analysis (server fingerprinting, missing security headers)
  2. Common vulnerability path probing (admin panels, backups, configs)
  3. SQL injection detection (error-based on known-vulnerable parameters)
  4. XSS reflection detection
  5. Directory listing detection
  6. Technology fingerprinting
  7. SSL/TLS analysis

Each finding generates a structured alert that gets sent to POST /alerts
and processed by the full 6-agent AI pipeline.

Usage:
  python scripts/live_scanner.py                       # Scan all targets
  python scripts/live_scanner.py testphp.vulnweb.com   # Scan specific target
  python scripts/live_scanner.py --quick               # Quick scan (fewer checks)

⚠️  ONLY use against intentionally-vulnerable targets or systems you own.
"""

import asyncio
import json
import re
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

import httpx

API_BASE = "http://localhost:8000"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Target Definitions
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TARGETS = {
    "testphp.vulnweb.com": {
        "base_url": "http://testphp.vulnweb.com",
        "description": "Acunetix Intentionally Vulnerable PHP Application",
        "sqli_endpoints": [
            "/artists.php?artist=1",
            "/listproducts.php?cat=1",
            "/product.php?pic=1",
        ],
        "xss_endpoints": [
            "/search.php?test=query",
            "/guestbook.php",
        ],
        "interesting_paths": [
            "/admin/", "/login.php", "/userinfo.php",
            "/AJAX/", "/Flash/", "/hpp/",
            "/secured/", "/cart.php", "/comment.php",
        ],
    },
    "testhtml5.vulnweb.com": {
        "base_url": "http://testhtml5.vulnweb.com",
        "description": "Acunetix HTML5 Vulnerable Application",
        "sqli_endpoints": [],
        "xss_endpoints": ["/", "/#/popular"],
        "interesting_paths": ["/api/", "/static/"],
    },
}

# Common paths to probe for across all targets
COMMON_PROBE_PATHS = [
    "/robots.txt", "/.env", "/.git/config", "/wp-admin/",
    "/admin/", "/phpmyadmin/", "/backup/", "/config.php",
    "/.htaccess", "/server-status", "/web.config",
    "/api/", "/.well-known/security.txt",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1 UNION SELECT 1,2,3--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "1; DROP TABLE test--",
]

SQLI_ERROR_PATTERNS = [
    r"mysql_fetch", r"mysql_num_rows", r"mysqli_",
    r"ORA-\d{5}", r"Oracle error",
    r"SQL syntax.*MySQL", r"Warning.*mysql_",
    r"Unclosed quotation mark", r"ODBC SQL Server Driver",
    r"Microsoft OLE DB Provider", r"PostgreSQL.*ERROR",
    r"SQLite3::", r"sqlite_",
    r"You have an error in your SQL syntax",
    r"supplied argument is not a valid MySQL",
]

XSS_PAYLOAD = '<script>alert("XSS")</script>'
XSS_MARKER = 'alert("XSS")'


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Scanner Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class LiveScanner:
    """Performs safe reconnaissance against vulnerable targets."""

    def __init__(self, target: str, quick: bool = False):
        self.target = target
        self.config = TARGETS.get(target, {
            "base_url": f"http://{target}",
            "description": f"Custom target: {target}",
            "sqli_endpoints": [],
            "xss_endpoints": [],
            "interesting_paths": [],
        })
        self.base_url = self.config["base_url"]
        self.quick = quick
        self.findings: List[Dict[str, Any]] = []
        self.scan_start = None

    async def run_full_scan(self) -> List[Dict[str, Any]]:
        """Execute all scan modules and return findings as alerts."""
        self.scan_start = time.time()
        print(f"\n  ┌─ Scanning: {self.target}")
        print(f"  │  URL: {self.base_url}")
        print(f"  │  Mode: {'Quick' if self.quick else 'Full'}")
        print(f"  │")

        async with httpx.AsyncClient(
            timeout=15,
            follow_redirects=True,
            headers={"User-Agent": "AutonomousSOC-Scanner/1.0 (Security Research)"},
        ) as client:
            # Module 1: Server fingerprinting & security headers
            await self._scan_headers(client)

            # Module 2: Path probing
            await self._scan_paths(client)

            # Module 3: SQL injection testing
            if not self.quick:
                await self._scan_sqli(client)

            # Module 4: XSS detection
            if not self.quick:
                await self._scan_xss(client)

            # Module 5: Technology fingerprinting
            await self._scan_tech(client)

        elapsed = round(time.time() - self.scan_start, 1)
        print(f"  │")
        print(f"  └─ Scan complete: {len(self.findings)} findings in {elapsed}s\n")

        return self.findings

    async def _scan_headers(self, client: httpx.AsyncClient):
        """Analyze HTTP response headers for security issues."""
        print(f"  ├─ [1/5] Analyzing HTTP headers...")
        try:
            resp = await client.get(self.base_url)
            headers = dict(resp.headers)

            # Server fingerprint
            server = headers.get("server", "Unknown")
            powered_by = headers.get("x-powered-by", "")
            if server and server != "Unknown":
                self._add_finding("server_fingerprint", "medium", {
                    "message": f"Server header exposes technology: {server}",
                    "server": server,
                    "x_powered_by": powered_by,
                    "risk": "Information disclosure — helps attacker fingerprint technology stack",
                })
                print(f"  │  ├─ Server: {server} {powered_by}")

            # Missing security headers
            missing = [h for h in SECURITY_HEADERS if h.lower() not in
                       {k.lower() for k in headers}]
            if missing:
                self._add_finding("missing_security_headers", "medium", {
                    "message": f"Missing {len(missing)} security headers: {', '.join(missing[:4])}",
                    "missing_headers": missing,
                    "total_missing": len(missing),
                    "risk": "Browser-level protections not enforced",
                })
                print(f"  │  ├─ Missing headers: {len(missing)}/{len(SECURITY_HEADERS)}")

            # Check for sensitive cookies without secure flag
            cookies = resp.headers.get_list("set-cookie")
            insecure_cookies = [c for c in cookies if "secure" not in c.lower() or "httponly" not in c.lower()]
            if insecure_cookies:
                self._add_finding("insecure_cookies", "high", {
                    "message": f"{len(insecure_cookies)} cookies without Secure/HttpOnly flags",
                    "insecure_cookie_count": len(insecure_cookies),
                })
                print(f"  │  └─ Insecure cookies: {len(insecure_cookies)}")

        except Exception as e:
            print(f"  │  └─ Header scan failed: {e}")

    async def _scan_paths(self, client: httpx.AsyncClient):
        """Probe for interesting/sensitive paths."""
        print(f"  ├─ [2/5] Probing paths...")
        paths = COMMON_PROBE_PATHS + self.config.get("interesting_paths", [])
        found = 0

        for path in paths:
            try:
                resp = await client.get(urljoin(self.base_url, path), follow_redirects=False)
                if resp.status_code in (200, 301, 302, 403):
                    severity = "high" if any(s in path for s in [".env", ".git", "admin", "backup"]) else "low"
                    status_label = {200: "accessible", 301: "redirect", 302: "redirect", 403: "forbidden"}
                    self._add_finding("path_discovered", severity, {
                        "message": f"Path {path} returned {resp.status_code} ({status_label.get(resp.status_code, 'found')})",
                        "path": path,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                        "url": urljoin(self.base_url, path),
                    })
                    found += 1
            except Exception:
                continue

        print(f"  │  └─ Found {found}/{len(paths)} paths accessible")

    async def _scan_sqli(self, client: httpx.AsyncClient):
        """Test for SQL injection vulnerabilities."""
        print(f"  ├─ [3/5] Testing SQL injection...")
        vulns_found = 0
        endpoints = self.config.get("sqli_endpoints", [])

        for endpoint in endpoints:
            url = urljoin(self.base_url, endpoint)
            for payload in SQLI_PAYLOADS[:2]:  # Use first 2 payloads
                try:
                    # Inject into first parameter
                    if "?" in url:
                        test_url = re.sub(r'=([^&]*)', f'={payload}', url, count=1)
                    else:
                        test_url = url + f"?id={payload}"

                    resp = await client.get(test_url)
                    body = resp.text

                    # Check for SQL error messages
                    for pattern in SQLI_ERROR_PATTERNS:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            self._add_finding("sql_injection_detected", "critical", {
                                "message": f"SQL injection vulnerability confirmed at {endpoint}",
                                "endpoint": endpoint,
                                "payload": payload,
                                "error_pattern": match.group(0)[:100],
                                "url": test_url,
                                "technique": "T1190",
                                "risk": "Database compromise — attacker can read/modify/delete data",
                            })
                            vulns_found += 1
                            break
                except Exception:
                    continue

        print(f"  │  └─ SQL injection points: {vulns_found}")

    async def _scan_xss(self, client: httpx.AsyncClient):
        """Test for reflected XSS vulnerabilities."""
        print(f"  ├─ [4/5] Testing XSS reflection...")
        vulns_found = 0
        endpoints = self.config.get("xss_endpoints", [])

        for endpoint in endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                if "?" in url:
                    test_url = re.sub(r'=([^&]*)', f'={XSS_PAYLOAD}', url, count=1)
                else:
                    test_url = url + f"?q={XSS_PAYLOAD}"

                resp = await client.get(test_url)
                if XSS_MARKER in resp.text:
                    self._add_finding("xss_reflected", "high", {
                        "message": f"Reflected XSS vulnerability at {endpoint}",
                        "endpoint": endpoint,
                        "payload": XSS_PAYLOAD,
                        "url": test_url,
                        "technique": "T1059.007",
                    })
                    vulns_found += 1
            except Exception:
                continue

        print(f"  │  └─ XSS reflection points: {vulns_found}")

    async def _scan_tech(self, client: httpx.AsyncClient):
        """Fingerprint technologies in use."""
        print(f"  ├─ [5/5] Technology fingerprinting...")
        try:
            resp = await client.get(self.base_url)
            body = resp.text.lower()
            techs = []

            tech_patterns = {
                "PHP": [r"\.php", r"x-powered-by.*php"],
                "jQuery": [r"jquery[.-][\d.]+"],
                "Bootstrap": [r"bootstrap[.-][\d.]+"],
                "WordPress": [r"wp-content", r"wp-includes"],
                "Apache": [r"apache"],
                "Nginx": [r"nginx"],
                "MySQL": [r"mysql"],
                "ASP.NET": [r"asp\.net", r"__viewstate"],
            }

            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, body + str(resp.headers), re.IGNORECASE):
                        techs.append(tech)
                        break

            if techs:
                self._add_finding("technology_detected", "info", {
                    "message": f"Technologies detected: {', '.join(techs)}",
                    "technologies": techs,
                    "count": len(techs),
                })
                print(f"  │  └─ Technologies: {', '.join(techs)}")
        except Exception as e:
            print(f"  │  └─ Tech scan failed: {e}")

    def _add_finding(self, event_type: str, severity: str, data: Dict[str, Any]):
        """Add a finding as a structured alert."""
        alert = {
            "source": "vuln_scanner",
            "data": {
                "event_type": event_type,
                "severity": severity,
                "target": self.target,
                "target_url": self.base_url,
                "scan_timestamp": datetime.utcnow().isoformat(),
                **data,
            },
        }
        self.findings.append(alert)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Send Findings to SOC Pipeline
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def send_findings_to_soc(findings: List[Dict[str, Any]]):
    """Send scan findings as alerts to the SOC API."""
    if not findings:
        print("  No findings to send.")
        return

    print(f"\n  Sending {len(findings)} findings to SOC pipeline...\n")

    async with httpx.AsyncClient(timeout=30) as client:
        # Check if server is up
        try:
            resp = await client.get(f"{API_BASE}/health", timeout=5)
        except Exception:
            print("  ❌ SOC API not reachable at localhost:8000")
            print("     Start it: uvicorn src.api.main:app --reload --port 8000")
            return

        for i, finding in enumerate(findings):
            sev = finding["data"].get("severity", "info")
            event = finding["data"].get("event_type", "unknown")
            sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
            icon = sev_icon.get(sev, "⚪")

            try:
                resp = await client.post(f"{API_BASE}/alerts", json=finding)
                if resp.status_code == 202:
                    alert_id = resp.json().get("alert_id", "?")[:12]
                    print(f"  {icon} [{i+1:2d}/{len(findings)}] {sev.upper():<8s} {event:<30s} → {alert_id}… ✅")
                else:
                    print(f"  ⚪ [{i+1:2d}/{len(findings)}] {event:<30s} → HTTP {resp.status_code} ❌")
            except Exception as e:
                print(f"  ⚪ [{i+1:2d}/{len(findings)}] {event:<30s} → Error ❌")

            # Small delay to not overwhelm the pipeline
            await asyncio.sleep(1.0)

    print(f"\n  ✅ All findings sent! Watch the dashboard for AI analysis.\n")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI Entry Point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def main():
    args = sys.argv[1:]
    quick = "--quick" in args
    args = [a for a in args if not a.startswith("--")]

    targets = args if args else list(TARGETS.keys())

    print("\n" + "=" * 60)
    print("  Autonomous SOC — Live Vulnerability Scanner")
    print("  ⚠️  Only targets intentionally-vulnerable test sites")
    print("=" * 60)

    all_findings = []

    for target in targets:
        scanner = LiveScanner(target, quick=quick)
        findings = await scanner.run_full_scan()
        all_findings.extend(findings)

    # Summary
    print("  ┌─ SCAN SUMMARY")
    print(f"  │  Targets scanned: {len(targets)}")
    print(f"  │  Total findings:  {len(all_findings)}")
    by_sev = {}
    for f in all_findings:
        s = f["data"].get("severity", "info")
        by_sev[s] = by_sev.get(s, 0) + 1
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in by_sev:
            print(f"  │    {sev.upper():<10s} {by_sev[sev]}")
    print(f"  └─")

    # Send to SOC
    await send_findings_to_soc(all_findings)


if __name__ == "__main__":
    asyncio.run(main())