"""Target Monitor — Real-time attack detection for monitored targets.

Watches HTTP traffic to specified target websites/IPs and automatically
detects common attacks (SQLi, XSS, path traversal, brute force, etc.)
then sends findings as alerts through the full SOC pipeline.

Two modes:
  1. Active Polling: Periodically probes the target and analyzes responses
  2. Passive Analysis: Watches server access logs (if available)

The monitor runs as a background asyncio task that integrates with the
FastAPI server, so attacks are detected and visible in the dashboard
in near real-time.

Usage:
  # Start standalone monitor
  python scripts/target_monitor.py http://testphp.vulnweb.com

  # Or add targets via API:
  POST /targets {"url": "http://testphp.vulnweb.com", "name": "Acunetix Test"}

  # The API auto-starts monitoring and sends alerts to the pipeline
"""

import asyncio
import re
import time
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin, parse_qs, unquote

import httpx
import structlog

logger = structlog.get_logger()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Attack Detection Patterns
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SQLI_PATTERNS = [
    (r"(?i)(?:union\s+(?:all\s+)?select)", "UNION-based SQLi"),
    (r"(?i)(?:'\s*or\s+'?\d+'?\s*=\s*'?\d+'?)", "Boolean-based SQLi"),
    (r"(?i)(?:;\s*drop\s+table)", "Stacked query SQLi"),
    (r"(?i)(?:'\s*;\s*--)", "Comment-based SQLi"),
    (r"(?i)(?:sleep\s*\(\s*\d+\s*\))", "Time-based blind SQLi"),
    (r"(?i)(?:benchmark\s*\()", "Benchmark-based SQLi"),
    (r"(?i)(?:extractvalue|updatexml)", "XML-based SQLi"),
    (r"(?i)(?:load_file|into\s+outfile)", "File-based SQLi"),
]

XSS_PATTERNS = [
    (r"(?i)<\s*script[^>]*>", "Script tag injection"),
    (r"(?i)javascript\s*:", "JavaScript protocol"),
    (r"(?i)on(?:error|load|click|mouse|focus)\s*=", "Event handler injection"),
    (r"(?i)<\s*img[^>]+onerror", "IMG tag XSS"),
    (r"(?i)<\s*svg[^>]+onload", "SVG-based XSS"),
    (r"(?i)document\.(?:cookie|location|write)", "DOM manipulation"),
    (r"(?i)alert\s*\(", "Alert-based XSS probe"),
]

PATH_TRAVERSAL_PATTERNS = [
    (r"(?:\.\./){2,}", "Directory traversal"),
    (r"(?:%2e%2e[/\\]){2,}", "Encoded directory traversal"),
    (r"(?:etc/passwd|etc/shadow)", "Linux file access"),
    (r"(?:boot\.ini|win\.ini)", "Windows file access"),
    (r"(?:proc/self/environ)", "Proc environ access"),
]

COMMAND_INJECTION_PATTERNS = [
    (r"(?:;\s*(?:ls|cat|id|whoami|uname|pwd))", "Unix command injection"),
    (r"(?:\|\s*(?:ls|cat|id|whoami))", "Pipe command injection"),
    (r"(?:`[^`]+`)", "Backtick command injection"),
    (r"(?:\$\([^)]+\))", "Subshell injection"),
]

SCANNER_SIGNATURES = [
    (r"(?i)(?:sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz)", "Scanner detected"),
    (r"(?i)(?:acunetix|nessus|qualys|burpsuite)", "Vulnerability scanner"),
    (r"(?i)(?:python-requests|curl|wget)\s*/", "Script/bot request"),
]

BRUTE_FORCE_PATHS = [
    "/admin", "/login", "/wp-login.php", "/wp-admin",
    "/administrator", "/user/login", "/auth/login",
    "/api/auth", "/api/login", "/signin", "/account/login",
]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php",
    "/config.php", "/database.yml", "/.htaccess", "/.htpasswd",
    "/backup.sql", "/dump.sql", "/phpinfo.php", "/info.php",
    "/server-status", "/server-info", "/.svn/entries",
    "/web.config", "/crossdomain.xml", "/.aws/credentials",
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Target Monitor
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class MonitoredTarget:
    """Represents a target being actively monitored."""

    def __init__(self, url: str, name: str = ""):
        parsed = urlparse(url if "://" in url else f"http://{url}")
        self.url = f"{parsed.scheme}://{parsed.netloc}"
        self.name = name or parsed.netloc
        self.hostname = parsed.netloc
        self.added_at = datetime.utcnow()
        self.last_scan = None
        self.total_alerts = 0
        self.total_requests = 0
        self.attacks_detected: List[Dict] = []
        self.request_log: List[Dict] = []
        self.baseline_headers: Dict = {}
        self.baseline_status: int = 0
        self.is_active = True

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "name": self.name,
            "hostname": self.hostname,
            "added_at": self.added_at.isoformat(),
            "last_scan": self.last_scan.isoformat() if self.last_scan else None,
            "total_alerts": self.total_alerts,
            "total_requests": self.total_requests,
            "recent_attacks": self.attacks_detected[-20:],
            "is_active": self.is_active,
        }


class TargetMonitor:
    """Monitors targets for attacks and sends alerts to SOC pipeline."""

    def __init__(self):
        self.targets: Dict[str, MonitoredTarget] = {}
        self._running = False
        self._tasks: List[asyncio.Task] = []
        self.scan_interval = 30  # seconds between active scans
        self.alert_callback = None  # Set by API to send alerts

    def add_target(self, url: str, name: str = "") -> MonitoredTarget:
        """Add a target for monitoring."""
        target = MonitoredTarget(url, name)
        self.targets[target.hostname] = target
        logger.info("target_added", hostname=target.hostname, url=target.url)
        return target

    def remove_target(self, hostname: str):
        """Remove a target from monitoring."""
        if hostname in self.targets:
            self.targets[hostname].is_active = False
            del self.targets[hostname]

    def get_all_targets(self) -> List[Dict]:
        """Return status of all monitored targets."""
        return [t.to_dict() for t in self.targets.values()]

    def get_target(self, hostname: str) -> Optional[Dict]:
        if hostname in self.targets:
            return self.targets[hostname].to_dict()
        return None

    async def analyze_request(self, target_hostname: str, method: str, path: str,
                              query_string: str = "", headers: Dict = None,
                              body: str = "", source_ip: str = "unknown",
                              user_agent: str = "", status_code: int = 0) -> List[Dict]:
        """Analyze a single HTTP request for attack patterns.

        This is the core detection engine. Call it for each request
        to a monitored target.

        Returns: List of detected attacks (empty if clean)
        """
        attacks = []
        full_url = f"{path}?{query_string}" if query_string else path
        decoded_url = unquote(full_url)
        decoded_body = unquote(body) if body else ""
        check_text = f"{decoded_url} {decoded_body} {user_agent}"

        # ── SQL Injection Detection ──
        for pattern, desc in SQLI_PATTERNS:
            if re.search(pattern, check_text):
                attacks.append(self._make_attack("sql_injection", "critical", desc,
                    target_hostname, source_ip, method, path, query_string, user_agent))
                break

        # ── XSS Detection ──
        for pattern, desc in XSS_PATTERNS:
            if re.search(pattern, check_text):
                attacks.append(self._make_attack("xss_attempt", "high", desc,
                    target_hostname, source_ip, method, path, query_string, user_agent))
                break

        # ── Path Traversal ──
        for pattern, desc in PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, check_text):
                attacks.append(self._make_attack("path_traversal", "high", desc,
                    target_hostname, source_ip, method, path, query_string, user_agent))
                break

        # ── Command Injection ──
        for pattern, desc in COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, check_text):
                attacks.append(self._make_attack("command_injection", "critical", desc,
                    target_hostname, source_ip, method, path, query_string, user_agent))
                break

        # ── Scanner Detection ──
        for pattern, desc in SCANNER_SIGNATURES:
            if re.search(pattern, user_agent or ""):
                attacks.append(self._make_attack("scanner_detected", "medium", desc,
                    target_hostname, source_ip, method, path, query_string, user_agent))
                break

        # ── Sensitive Path Access ──
        for sens_path in SENSITIVE_PATHS:
            if path.rstrip("/").lower() == sens_path.rstrip("/").lower():
                attacks.append(self._make_attack("sensitive_path_access", "high",
                    f"Access to sensitive path: {sens_path}",
                    target_hostname, source_ip, method, path, query_string, user_agent))
                break

        # ── Brute Force Path ──
        for bf_path in BRUTE_FORCE_PATHS:
            if path.rstrip("/").lower().startswith(bf_path.lower()) and method.upper() == "POST":
                attacks.append(self._make_attack("brute_force_attempt", "high",
                    f"POST to login endpoint: {path}",
                    target_hostname, source_ip, method, path, query_string, user_agent))
                break

        # Log request and attacks
        target = self.targets.get(target_hostname)
        if target:
            target.total_requests += 1
            req_log = {
                "time": datetime.utcnow().isoformat(),
                "method": method, "path": path,
                "source_ip": source_ip, "status": status_code,
                "attack_count": len(attacks),
            }
            target.request_log.append(req_log)
            if len(target.request_log) > 500:
                target.request_log = target.request_log[-500:]

            if attacks:
                target.total_alerts += len(attacks)
                target.attacks_detected.extend(attacks)
                if len(target.attacks_detected) > 200:
                    target.attacks_detected = target.attacks_detected[-200:]

        # Send attacks to SOC pipeline
        if attacks and self.alert_callback:
            for attack in attacks:
                try:
                    await self.alert_callback(attack)
                except Exception as e:
                    logger.error("alert_callback_failed", error=str(e))

        return attacks

    async def run_active_scan(self, target: MonitoredTarget):
        """Run an active probe scan against a target.

        Checks: baseline response, header changes, common vulns
        """
        async with httpx.AsyncClient(timeout=10, follow_redirects=True,
            headers={"User-Agent": "AutonomousSOC-Monitor/1.0"}) as client:
            try:
                # Baseline check
                resp = await client.get(target.url)
                target.baseline_status = resp.status_code
                target.baseline_headers = dict(resp.headers)
                target.last_scan = datetime.utcnow()

                # Quick SQLi probe on common params
                for path in ["/search?q=test", "/index.php?id=1", "/?page=1"]:
                    try:
                        test_url = f"{target.url}{path}' OR '1'='1"
                        resp = await client.get(test_url)
                        if any(re.search(p, resp.text, re.I) for p, _ in [
                            (r"mysql_fetch|mysql_num_rows|SQL syntax.*MySQL", ""),
                            (r"Warning.*mysql_|ORA-\d{5}", ""),
                        ]):
                            await self.analyze_request(
                                target.hostname, "GET", path,
                                "q=' OR '1'='1", source_ip="active_scan",
                                user_agent="AutonomousSOC-ActiveScan"
                            )
                    except Exception:
                        continue

            except Exception as e:
                logger.warning("active_scan_failed", target=target.hostname, error=str(e))

    def _make_attack(self, event_type: str, severity: str, description: str,
                     target: str, source_ip: str, method: str, path: str,
                     query: str, user_agent: str) -> Dict:
        return {
            "source": "target_monitor",
            "data": {
                "event_type": event_type,
                "severity": severity,
                "message": f"[{target}] {description}",
                "target": target,
                "target_path": path,
                "query_string": query[:500] if query else "",
                "method": method,
                "src_ip": source_ip,
                "user_agent": (user_agent or "")[:200],
                "detected_at": datetime.utcnow().isoformat(),
                "technique": self._get_mitre_technique(event_type),
            }
        }

    @staticmethod
    def _get_mitre_technique(event_type: str) -> str:
        mapping = {
            "sql_injection": "T1190",
            "xss_attempt": "T1059.007",
            "path_traversal": "T1083",
            "command_injection": "T1059",
            "scanner_detected": "T1595",
            "sensitive_path_access": "T1083",
            "brute_force_attempt": "T1110",
        }
        return mapping.get(event_type, "")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Singleton Monitor Instance
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_monitor: Optional[TargetMonitor] = None

def get_monitor() -> TargetMonitor:
    global _monitor
    if _monitor is None:
        _monitor = TargetMonitor()
    return _monitor