"""SOC URL Watcher — Paste URLs you visit and they get analyzed for attacks.

This is the simplest way to connect your browsing to the SOC dashboard.
No browser extensions, no proxy, no Chrome flags needed.

Mode 1 — Interactive: Paste URLs as you browse
Mode 2 — Auto-scan: Crawl a target and analyze all links
Mode 3 — Attack test: Run common attacks against a target

Usage:
  python scripts/url_watcher.py                              # Interactive mode
  python scripts/url_watcher.py --crawl testphp.vulnweb.com  # Auto-crawl
  python scripts/url_watcher.py --attack testphp.vulnweb.com # Run attack tests
"""

import asyncio
import re
import sys
import os
from urllib.parse import urlparse, urljoin, parse_qs, unquote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import httpx

SOC_API = "http://localhost:8000"


async def analyze_url(url: str):
    """Send a URL to the SOC for attack analysis."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or "/"
    query = parsed.query or ""

    payload = {
        "target": hostname,
        "method": "GET",
        "path": path,
        "query_string": query,
        "source_ip": "browser",
        "user_agent": "SOC-URLWatcher/1.0",
    }

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(f"{SOC_API}/targets/analyze", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                attacks = data.get("attacks_detected", 0)
                if attacks > 0:
                    for atk in data.get("attacks", []):
                        d = atk.get("data", {})
                        print(f"  🔴 ATTACK DETECTED: {d.get('event_type','?')} — {d.get('message','')[:70]}")
                    return attacks
                else:
                    print(f"  ✅ Clean: {path}{'?' + query[:50] if query else ''}")
                    return 0
    except Exception as e:
        print(f"  ❌ SOC unreachable: {e}")
        return -1


async def add_target(hostname: str):
    """Add target to SOC monitor."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(f"{SOC_API}/targets",
                json={"url": f"http://{hostname}", "name": hostname})
            print(f"  ✅ Target added: {hostname}")
    except Exception:
        print(f"  ⚠️  Could not add target (is server running?)")


async def interactive_mode():
    """Paste URLs as you browse — each one gets analyzed."""
    print("\n" + "=" * 60)
    print("  Autonomous SOC — URL Watcher (Interactive)")
    print("=" * 60)
    print()
    print("  Paste any URL you visit and it will be analyzed for attacks.")
    print("  The SOC dashboard will update in real-time.")
    print()
    print("  Examples to try on testphp.vulnweb.com:")
    print("    http://testphp.vulnweb.com/artists.php?artist=1' OR '1'='1")
    print("    http://testphp.vulnweb.com/search.php?test=<script>alert(1)</script>")
    print("    http://testphp.vulnweb.com/../../etc/passwd")
    print("    http://testphp.vulnweb.com/.env")
    print("    http://testphp.vulnweb.com/listproducts.php?cat=1 UNION SELECT 1,2,3--")
    print()
    print("  Type 'quit' to exit.")
    print()

    targets_added = set()

    while True:
        try:
            url = input("  URL> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not url or url.lower() == 'quit':
            break

        # Auto-add http:// if missing
        if not url.startswith("http"):
            url = "http://" + url

        # Auto-add target
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if hostname and hostname not in targets_added:
            await add_target(hostname)
            targets_added.add(hostname)

        await analyze_url(url)

    print("\n  Done. Check your dashboard for results.\n")


async def crawl_mode(target: str):
    """Crawl a target website and analyze all discovered links."""
    if not target.startswith("http"):
        target = "http://" + target

    parsed = urlparse(target)
    hostname = parsed.hostname
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    print(f"\n" + "=" * 60)
    print(f"  Autonomous SOC — Auto-Crawl: {hostname}")
    print(f"=" * 60)

    await add_target(hostname)

    visited = set()
    to_visit = [target]
    total_attacks = 0

    async with httpx.AsyncClient(timeout=10, follow_redirects=True,
        headers={"User-Agent": "SOC-Crawler/1.0"}) as client:

        while to_visit and len(visited) < 50:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            print(f"\n  [{len(visited)}] Crawling: {url}")
            attacks = await analyze_url(url)
            if attacks and attacks > 0:
                total_attacks += attacks

            # Extract links from page
            try:
                resp = await client.get(url)
                links = re.findall(r'href=["\']([^"\']+)', resp.text)
                for link in links:
                    full_url = urljoin(url, link)
                    link_parsed = urlparse(full_url)
                    if link_parsed.hostname == hostname and full_url not in visited:
                        to_visit.append(full_url)
            except Exception:
                continue

    print(f"\n  ┌─ CRAWL COMPLETE")
    print(f"  │  Pages crawled:    {len(visited)}")
    print(f"  │  Attacks detected: {total_attacks}")
    print(f"  └─")
    print(f"\n  Check your dashboard at http://localhost:8000/dashboard\n")


async def attack_mode(target: str):
    """Run common attack payloads against a target."""
    if not target.startswith("http"):
        target = "http://" + target

    parsed = urlparse(target)
    hostname = parsed.hostname
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    print(f"\n" + "=" * 60)
    print(f"  Autonomous SOC — Attack Tester: {hostname}")
    print(f"=" * 60)

    await add_target(hostname)

    attacks = [
        # SQL Injection
        f"{base_url}/artists.php?artist=1' OR '1'='1",
        f"{base_url}/listproducts.php?cat=1 UNION SELECT 1,2,3--",
        f"{base_url}/product.php?pic=1; DROP TABLE users--",
        f"{base_url}/search.php?test=' AND 1=CONVERT(int,@@version)--",
        # XSS
        f"{base_url}/search.php?test=<script>alert('XSS')</script>",
        f"{base_url}/guestbook.php?name=<img onerror=alert(1) src=x>",
        f"{base_url}/search.php?test=javascript:alert(document.cookie)",
        # Path Traversal
        f"{base_url}/../../etc/passwd",
        f"{base_url}/....//....//etc/shadow",
        # Sensitive Files
        f"{base_url}/.env",
        f"{base_url}/.git/config",
        f"{base_url}/.htaccess",
        f"{base_url}/phpinfo.php",
        f"{base_url}/wp-config.php",
        f"{base_url}/backup.sql",
        # Admin / Brute Force paths
        f"{base_url}/admin/",
        f"{base_url}/wp-admin/",
        f"{base_url}/phpmyadmin/",
        # Scanner signatures (via user-agent in analyze)
        f"{base_url}/index.php",  # will send with scanner UA
        # Command injection
        f"{base_url}/search.php?test=;ls -la",
        f"{base_url}/search.php?test=|cat /etc/passwd",
    ]

    total_detected = 0
    for i, url in enumerate(attacks):
        print(f"\n  [{i+1:2d}/{len(attacks)}] {url[:80]}")
        count = await analyze_url(url)
        if count and count > 0:
            total_detected += count
        await asyncio.sleep(0.5)

    print(f"\n  ┌─ ATTACK TEST COMPLETE")
    print(f"  │  Payloads sent:     {len(attacks)}")
    print(f"  │  Attacks detected:  {total_detected}")
    print(f"  │  Detection rate:    {total_detected/len(attacks)*100:.0f}%")
    print(f"  └─")
    print(f"\n  Check your dashboard at http://localhost:8000/dashboard\n")


async def main():
    args = sys.argv[1:]

    if "--crawl" in args:
        idx = args.index("--crawl")
        target = args[idx + 1] if idx + 1 < len(args) else "testphp.vulnweb.com"
        await crawl_mode(target)
    elif "--attack" in args:
        idx = args.index("--attack")
        target = args[idx + 1] if idx + 1 < len(args) else "testphp.vulnweb.com"
        await attack_mode(target)
    else:
        await interactive_mode()


if __name__ == "__main__":
    asyncio.run(main())