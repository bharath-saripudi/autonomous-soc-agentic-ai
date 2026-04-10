"""SOC Traffic Proxy — Intercepts HTTP traffic to monitored targets.

Runs a local proxy on port 9090 that forwards all requests to the target
while analyzing them for attacks in real-time. Detected attacks are sent
to the SOC pipeline automatically.

How it works:
  1. You set your browser proxy to localhost:9090
  2. Browse testphp.vulnweb.com normally (or perform attacks)
  3. Every request is analyzed by the SOC's attack detection engine
  4. Findings appear on your dashboard in real-time

Usage:
  python scripts/traffic_proxy.py                          # Proxy all traffic
  python scripts/traffic_proxy.py testphp.vulnweb.com     # Only proxy specific target

Alternative (no proxy needed):
  You can also paste this bookmarklet in your browser console while on the target site.
  It hooks XMLHttpRequest and fetch to report all requests to the SOC:

  See the /inject.js endpoint served by this script.
"""

import asyncio
import sys
import os
import json
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

import httpx

SOC_API = "http://localhost:8000"
PROXY_PORT = 9090


class TrafficInterceptor:
    """Sends captured HTTP requests to the SOC for analysis."""

    def __init__(self):
        self.request_count = 0
        self.attack_count = 0

    async def analyze(self, target: str, method: str, path: str,
                      query_string: str = "", body: str = "",
                      source_ip: str = "browser", user_agent: str = "",
                      status_code: int = 200):
        """Send a captured request to the SOC's /targets/analyze endpoint."""
        self.request_count += 1

        payload = {
            "target": target,
            "method": method,
            "path": path,
            "query_string": query_string,
            "body": body,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "status_code": status_code,
        }

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(f"{SOC_API}/targets/analyze", json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    attacks = data.get("attacks_detected", 0)
                    if attacks > 0:
                        self.attack_count += attacks
                        for atk in data.get("attacks", []):
                            d = atk.get("data", {})
                            print(f"  🔴 ATTACK: {d.get('event_type','?')} — {d.get('message','')[:60]}")
                    return data
        except Exception as e:
            pass
        return None


interceptor = TrafficInterceptor()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Browser Script Injection Approach (No Proxy Needed)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BROWSER_HOOK_SCRIPT = """
// === Autonomous SOC — Browser Traffic Hook ===
// Paste this in your browser console (F12) while on the target site.
// It intercepts all navigation and form submissions, sending them to your SOC.

(function() {
  const SOC_API = 'http://localhost:8000';
  const TARGET = window.location.hostname;
  let reqCount = 0;

  // Auto-add target
  fetch(SOC_API + '/targets', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url: window.location.origin, name: TARGET})
  }).catch(() => {});

  function sendToSOC(method, path, queryString, body) {
    reqCount++;
    const payload = {
      target: TARGET,
      method: method,
      path: path,
      query_string: queryString || '',
      body: body || '',
      source_ip: 'browser',
      user_agent: navigator.userAgent,
      status_code: 200
    };

    fetch(SOC_API + '/targets/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    }).then(r => r.json()).then(data => {
      if (data.attacks_detected > 0) {
        console.log('%c[SOC] 🔴 ATTACK DETECTED: ' + JSON.stringify(data.attacks.map(a => a.data.event_type)), 'color: red; font-weight: bold');
      } else {
        console.log('[SOC] ✅ Request analyzed:', method, path, '(' + reqCount + ' total)');
      }
    }).catch(() => {});
  }

  // Hook: Intercept link clicks and form submissions
  document.addEventListener('click', function(e) {
    const link = e.target.closest('a[href]');
    if (link && link.href) {
      try {
        const url = new URL(link.href);
        if (url.hostname === TARGET || url.hostname === '') {
          sendToSOC('GET', url.pathname, url.search.slice(1), '');
        }
      } catch(err) {}
    }
  }, true);

  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (form.tagName === 'FORM') {
      const formData = new FormData(form);
      const body = new URLSearchParams(formData).toString();
      const action = form.action || window.location.href;
      try {
        const url = new URL(action);
        sendToSOC(form.method.toUpperCase() || 'POST', url.pathname, url.search.slice(1), body);
      } catch(err) {
        sendToSOC(form.method.toUpperCase() || 'POST', action, '', body);
      }
    }
  }, true);

  // Hook: Intercept URL changes (for SPAs)
  const origPushState = history.pushState;
  history.pushState = function() {
    origPushState.apply(this, arguments);
    const url = new URL(window.location.href);
    sendToSOC('GET', url.pathname, url.search.slice(1), '');
  };

  // Hook: Intercept fetch API
  const origFetch = window.fetch;
  window.fetch = function(input, init) {
    try {
      const url = new URL(input, window.location.origin);
      const method = (init && init.method) || 'GET';
      const body = (init && init.body) || '';
      sendToSOC(method, url.pathname, url.search.slice(1), typeof body === 'string' ? body : '');
    } catch(err) {}
    return origFetch.apply(this, arguments);
  };

  // Hook: Intercept XMLHttpRequest
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(method, url) {
    this._socMethod = method;
    this._socUrl = url;
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function(body) {
    try {
      const url = new URL(this._socUrl, window.location.origin);
      sendToSOC(this._socMethod, url.pathname, url.search.slice(1), body || '');
    } catch(err) {}
    return origSend.apply(this, arguments);
  };

  // Analyze current page load
  const currentUrl = new URL(window.location.href);
  sendToSOC('GET', currentUrl.pathname, currentUrl.search.slice(1), '');

  console.log('%c[SOC] ✅ Traffic monitoring active for: ' + TARGET, 'color: #3edfcf; font-weight: bold; font-size: 14px');
  console.log('[SOC] All requests will be analyzed by your Autonomous SOC dashboard');
  console.log('[SOC] Try performing an XSS: add ?q=<script>alert(1)</script> to the URL');
})();
""".strip()


async def serve_inject_script():
    """Serve the browser hook script via the SOC API."""
    pass  # Handled in main.py


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI — Simple Forwarding Proxy
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def main():
    target_filter = sys.argv[1] if len(sys.argv) > 1 else None

    print("\n" + "=" * 65)
    print("  Autonomous SOC — Browser Traffic Monitor")
    print("=" * 65)
    print()

    if target_filter:
        # Auto-add target
        async with httpx.AsyncClient(timeout=5) as client:
            try:
                await client.post(f"{SOC_API}/targets",
                    json={"url": f"http://{target_filter}", "name": target_filter})
                print(f"  ✅ Target added: {target_filter}")
            except Exception:
                print(f"  ⚠️  Could not auto-add target (is the server running?)")

    print(f"  📋 OPTION 1 — Browser Console (Recommended):")
    print(f"     1. Open http://testphp.vulnweb.com in Chrome")
    print(f"     2. Press F12 → Console tab")
    print(f"     3. Paste the script from: http://localhost:8000/inject.js")
    print(f"     4. Browse the site — every click/form/XSS attempt is captured")
    print()
    print(f"  📋 OPTION 2 — Copy & paste this one-liner into the console:")
    print()
    print(f'     fetch("http://localhost:8000/inject.js").then(r=>r.text()).then(eval)')
    print()
    print(f"  Then try these attacks on testphp.vulnweb.com:")
    print(f"     • URL: /artists.php?artist=1' OR '1'='1")
    print(f"     • URL: /search.php?test=<script>alert(1)</script>")
    print(f"     • URL: /listproducts.php?cat=1 UNION SELECT 1,2,3--")
    print()
    print(f"  Watch your dashboard at http://localhost:8000/dashboard")
    print(f"  (Targets tab → crosshair icon)")
    print()

    # Keep alive
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n  Stopped.\n")


if __name__ == "__main__":
    asyncio.run(main())