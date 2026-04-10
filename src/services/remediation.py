"""Remediation Engine — Maps detected attacks to fix suggestions.

Provides actionable remediation advice for each attack type including:
  - What the vulnerability is and why it's dangerous
  - Specific code fixes with before/after examples
  - Configuration changes needed
  - OWASP reference links
  - Priority level (immediate / short-term / long-term)

Used by the Response Agent to attach fix suggestions to every alert,
and displayed in the dashboard's alert detail view.
"""

from typing import Any, Dict, List, Optional


REMEDIATION_DB = {
    "sql_injection": {
        "title": "SQL Injection (SQLi)",
        "severity": "critical",
        "owasp": "A03:2021 - Injection",
        "description": "Attacker can execute arbitrary SQL queries, potentially reading, modifying, or deleting all database contents.",
        "immediate_actions": [
            "Block the attacking IP address at the WAF/firewall",
            "Review database logs for unauthorized data access",
            "Check if any data was exfiltrated",
            "Rotate database credentials if compromise is confirmed",
        ],
        "fix_steps": [
            {
                "title": "Use Parameterized Queries (Prepared Statements)",
                "priority": "immediate",
                "description": "Never concatenate user input into SQL strings. Use parameterized queries instead.",
                "vulnerable_code": "query = \"SELECT * FROM users WHERE id = '\" + user_input + \"'\"",
                "fixed_code": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_input,))",
                "language": "python",
            },
            {
                "title": "Use an ORM (SQLAlchemy, Django ORM)",
                "priority": "short-term",
                "description": "ORMs automatically parameterize queries and prevent injection.",
                "vulnerable_code": "db.execute(f\"SELECT * FROM products WHERE cat={request.args['cat']}\")",
                "fixed_code": "Product.query.filter_by(category=request.args['cat']).all()",
                "language": "python",
            },
            {
                "title": "Input Validation & WAF Rules",
                "priority": "immediate",
                "description": "Validate and sanitize all user inputs. Deploy WAF rules to block common SQLi patterns.",
                "vulnerable_code": "# No validation\nartist_id = request.GET['artist']",
                "fixed_code": "# Validate input type\nartist_id = int(request.GET.get('artist', 0))  # Rejects non-numeric input",
                "language": "python",
            },
        ],
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "xss_attempt": {
        "title": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "owasp": "A07:2021 - Cross-Site Scripting",
        "description": "Attacker can inject malicious scripts into web pages viewed by other users, stealing sessions, credentials, or defacing the site.",
        "immediate_actions": [
            "Enable Content-Security-Policy (CSP) headers",
            "Review affected pages for stored XSS payloads",
            "Invalidate active sessions if stored XSS confirmed",
        ],
        "fix_steps": [
            {
                "title": "HTML-Encode All User Output",
                "priority": "immediate",
                "description": "Escape all user-controlled data before rendering in HTML.",
                "vulnerable_code": "<p>Search results for: {{ user_input }}</p>",
                "fixed_code": "<p>Search results for: {{ user_input | escape }}</p>",
                "language": "html",
            },
            {
                "title": "Set Content-Security-Policy Header",
                "priority": "immediate",
                "description": "CSP blocks inline scripts even if XSS exists.",
                "vulnerable_code": "# No CSP header set",
                "fixed_code": "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
                "language": "http",
            },
            {
                "title": "Use HttpOnly and Secure Cookie Flags",
                "priority": "short-term",
                "description": "Prevents JavaScript from accessing session cookies even if XSS succeeds.",
                "vulnerable_code": "Set-Cookie: session=abc123",
                "fixed_code": "Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict",
                "language": "http",
            },
        ],
        "references": [
            "https://owasp.org/Top10/A07_2021-Cross-Site_Scripting/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    "path_traversal": {
        "title": "Path Traversal / Directory Traversal",
        "severity": "high",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Attacker can access files outside the intended directory, potentially reading sensitive system files like /etc/passwd or application config.",
        "immediate_actions": [
            "Block requests containing '../' patterns at the WAF",
            "Audit which files were accessed",
            "Review file permission settings on the server",
        ],
        "fix_steps": [
            {
                "title": "Validate and Canonicalize File Paths",
                "priority": "immediate",
                "description": "Resolve the real path and verify it's within the allowed directory.",
                "vulnerable_code": "file_path = '/uploads/' + request.args['file']",
                "fixed_code": "import os\nbase = '/uploads'\npath = os.path.realpath(os.path.join(base, request.args['file']))\nif not path.startswith(base):\n    abort(403)",
                "language": "python",
            },
            {
                "title": "Use Allowlists Instead of Blocklists",
                "priority": "short-term",
                "description": "Instead of blocking '../', only allow specific filenames or patterns.",
                "vulnerable_code": "if '../' not in filename:  # Bypassable!",
                "fixed_code": "ALLOWED = {'report.pdf', 'data.csv'}\nif filename not in ALLOWED:\n    abort(403)",
                "language": "python",
            },
        ],
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://owasp.org/www-community/attacks/Path_Traversal",
        ],
    },
    "command_injection": {
        "title": "OS Command Injection",
        "severity": "critical",
        "owasp": "A03:2021 - Injection",
        "description": "Attacker can execute arbitrary operating system commands on the server, potentially gaining full control of the system.",
        "immediate_actions": [
            "Immediately isolate the affected server",
            "Check for unauthorized processes and backdoors",
            "Review command history and access logs",
            "Rotate all credentials on the affected system",
        ],
        "fix_steps": [
            {
                "title": "Never Pass User Input to Shell Commands",
                "priority": "immediate",
                "description": "Use language-native APIs instead of shell commands.",
                "vulnerable_code": "os.system('ping ' + user_input)",
                "fixed_code": "import subprocess\nsubprocess.run(['ping', '-c', '3', validated_ip], capture_output=True)",
                "language": "python",
            },
            {
                "title": "Use Allowlists for Command Arguments",
                "priority": "immediate",
                "description": "If shell commands are unavoidable, strictly validate inputs.",
                "vulnerable_code": "os.popen(f'nslookup {domain}')",
                "fixed_code": "import re\nif not re.match(r'^[a-zA-Z0-9.-]+$', domain):\n    raise ValueError('Invalid domain')\nsubprocess.run(['nslookup', domain])",
                "language": "python",
            },
        ],
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
    },
    "sensitive_path_access": {
        "title": "Sensitive File Exposure",
        "severity": "high",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Sensitive files (.env, .git, backups, configs) are accessible via the web, potentially exposing credentials, API keys, and source code.",
        "immediate_actions": [
            "Immediately block access to the exposed files",
            "Rotate any credentials found in exposed files",
            "Check Git history for previously committed secrets",
        ],
        "fix_steps": [
            {
                "title": "Block Sensitive Paths in Web Server Config",
                "priority": "immediate",
                "description": "Configure Nginx/Apache to deny access to sensitive files.",
                "vulnerable_code": "# No rules — all files accessible",
                "fixed_code": "# Nginx\nlocation ~ /\\.(env|git|htaccess|htpasswd) {\n    deny all;\n    return 404;\n}",
                "language": "nginx",
            },
            {
                "title": "Move Sensitive Files Outside Web Root",
                "priority": "short-term",
                "description": "Store .env, configs, and backups outside the publicly accessible directory.",
                "vulnerable_code": "/var/www/html/.env\n/var/www/html/backup.sql",
                "fixed_code": "/etc/myapp/.env  (outside web root)\n/var/backups/db/  (outside web root)",
                "language": "bash",
            },
        ],
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    },
    "scanner_detected": {
        "title": "Automated Vulnerability Scanner Detected",
        "severity": "medium",
        "owasp": "Reconnaissance",
        "description": "An automated scanning tool (sqlmap, nikto, nmap, etc.) is probing the application for vulnerabilities. This is typically a precursor to an actual attack.",
        "immediate_actions": [
            "Block the scanner's IP address",
            "Enable rate limiting on the target application",
            "Review logs for any successful exploitation attempts",
        ],
        "fix_steps": [
            {
                "title": "Implement Rate Limiting",
                "priority": "immediate",
                "description": "Limit requests per IP to prevent automated scanning.",
                "vulnerable_code": "# No rate limiting",
                "fixed_code": "# Nginx rate limiting\nlimit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\nlimit_req zone=api burst=20 nodelay;",
                "language": "nginx",
            },
            {
                "title": "Deploy a Web Application Firewall (WAF)",
                "priority": "short-term",
                "description": "WAFs like ModSecurity, Cloudflare, or AWS WAF can detect and block scanner signatures.",
                "vulnerable_code": "# No WAF protection",
                "fixed_code": "# ModSecurity with OWASP CRS\nSecRuleEngine On\nInclude /etc/modsecurity/owasp-crs/crs-setup.conf",
                "language": "apache",
            },
        ],
        "references": [
            "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
        ],
    },
    "brute_force_attempt": {
        "title": "Brute Force / Credential Stuffing",
        "severity": "high",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "Attacker is attempting to guess credentials through repeated login attempts, potentially compromising user accounts.",
        "immediate_actions": [
            "Enable account lockout after 5 failed attempts",
            "Block the attacking IP address",
            "Notify affected users to change passwords",
            "Check for any successful logins from the attacker IP",
        ],
        "fix_steps": [
            {
                "title": "Implement Account Lockout",
                "priority": "immediate",
                "description": "Lock accounts after repeated failed login attempts.",
                "vulnerable_code": "# No lockout — unlimited login attempts allowed",
                "fixed_code": "MAX_ATTEMPTS = 5\nLOCKOUT_MINUTES = 30\n\nif failed_attempts >= MAX_ATTEMPTS:\n    lock_account(username, duration=LOCKOUT_MINUTES)",
                "language": "python",
            },
            {
                "title": "Add CAPTCHA After Failed Attempts",
                "priority": "short-term",
                "description": "Show CAPTCHA after 3 failed attempts to block automated tools.",
                "vulnerable_code": "# Direct login form — no bot protection",
                "fixed_code": "if failed_count >= 3:\n    require_captcha()\n# Use reCAPTCHA v3 for invisible protection",
                "language": "python",
            },
            {
                "title": "Enforce Multi-Factor Authentication (MFA)",
                "priority": "long-term",
                "description": "Even if credentials are compromised, MFA prevents unauthorized access.",
                "vulnerable_code": "# Password-only authentication",
                "fixed_code": "# Add TOTP-based MFA\nimport pyotp\ntotp = pyotp.TOTP(user.mfa_secret)\nif not totp.verify(request.form['mfa_code']):\n    abort(401, 'Invalid MFA code')",
                "language": "python",
            },
        ],
        "references": [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        ],
    },
    "missing_security_headers": {
        "title": "Missing Security Headers",
        "severity": "medium",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "The web server is missing critical security headers that protect against XSS, clickjacking, MIME sniffing, and other browser-based attacks.",
        "immediate_actions": [
            "Add security headers to the web server configuration",
        ],
        "fix_steps": [
            {
                "title": "Add All Recommended Security Headers",
                "priority": "immediate",
                "description": "Add these headers to your Nginx/Apache/Express configuration.",
                "vulnerable_code": "# No security headers configured",
                "fixed_code": "# Nginx — add to server block\nadd_header X-Frame-Options \"DENY\";\nadd_header X-Content-Type-Options \"nosniff\";\nadd_header X-XSS-Protection \"1; mode=block\";\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";\nadd_header Content-Security-Policy \"default-src 'self'\";\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\";\nadd_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\";",
                "language": "nginx",
            },
        ],
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://securityheaders.com/",
        ],
    },
}

# Fallback for unknown attack types
DEFAULT_REMEDIATION = {
    "title": "Security Alert",
    "severity": "medium",
    "owasp": "General",
    "description": "A security event was detected. Review the alert details and take appropriate action.",
    "immediate_actions": [
        "Review the alert details and raw data",
        "Check system logs for related activity",
        "Block suspicious IPs if confirmed malicious",
    ],
    "fix_steps": [],
    "references": ["https://owasp.org/Top10/"],
}


def get_remediation(event_type: str) -> Dict[str, Any]:
    """Get remediation advice for an attack type."""
    return REMEDIATION_DB.get(event_type, DEFAULT_REMEDIATION)


def get_remediation_for_alert(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract event type from alert data and return remediation."""
    raw = alert_data.get("raw_data") or alert_data.get("data") or {}
    event_type = raw.get("event_type", "")

    # Try exact match first
    if event_type in REMEDIATION_DB:
        return REMEDIATION_DB[event_type]

    # Try partial match
    for key in REMEDIATION_DB:
        if key in event_type or event_type in key:
            return REMEDIATION_DB[key]

    # Check description/message for clues
    message = str(raw.get("message", "") or raw.get("description", "")).lower()
    if "sql" in message or "injection" in message or "union" in message:
        return REMEDIATION_DB["sql_injection"]
    if "xss" in message or "script" in message or "cross-site" in message:
        return REMEDIATION_DB["xss_attempt"]
    if "traversal" in message or "etc/passwd" in message:
        return REMEDIATION_DB["path_traversal"]
    if "brute" in message or "login" in message or "credential" in message:
        return REMEDIATION_DB["brute_force_attempt"]

    return DEFAULT_REMEDIATION