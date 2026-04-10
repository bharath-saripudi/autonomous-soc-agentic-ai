"""Threat Intelligence API Wrappers — VirusTotal and AbuseIPDB.

Uses httpx (pure Python, no C compilation needed on Windows ARM64).
All lookups go through Redis cache first (1-hour TTL).
"""

import time
from typing import Any, Dict

import httpx
import structlog

from src.config import get_settings
from src.services.cache import get_cache

logger = structlog.get_logger()
settings = get_settings()


class ThreatIntelError(Exception):
    pass


async def lookup_ip_abuseipdb(ip: str) -> Dict[str, Any]:
    cache = get_cache()
    cache_key = f"abuseipdb:ip:{ip}"
    cached = await cache.get(cache_key)
    if cached:
        return {**cached, "_cache": "hit"}
    if not settings.abuseipdb_api_key:
        return _empty_ip_result(ip, "abuseipdb", "no_api_key")
    start_time = time.time()
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            )
            if resp.status_code == 429:
                return _empty_ip_result(ip, "abuseipdb", "rate_limited")
            if resp.status_code != 200:
                return _empty_ip_result(ip, "abuseipdb", f"http_{resp.status_code}")
            data = resp.json().get("data", {})
        result = {
            "ip": ip, "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode"), "isp": data.get("isp"),
            "domain": data.get("domain"), "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "is_tor": data.get("isTor", False), "is_whitelisted": data.get("isWhitelisted", False),
            "last_reported": data.get("lastReportedAt"), "usage_type": data.get("usageType"),
            "source": "abuseipdb", "_cache": "miss",
        }
        await cache.set(cache_key, result)
        return result
    except httpx.HTTPError as e:
        return _empty_ip_result(ip, "abuseipdb", f"connection_error: {e}")


async def lookup_hash_virustotal(file_hash: str) -> Dict[str, Any]:
    cache = get_cache()
    cache_key = f"vt:hash:{file_hash}"
    cached = await cache.get(cache_key)
    if cached:
        return {**cached, "_cache": "hit"}
    if not settings.virustotal_api_key:
        return _empty_hash_result(file_hash, "no_api_key")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": settings.virustotal_api_key},
            )
            if resp.status_code == 404:
                result = _empty_hash_result(file_hash, "not_found")
                await cache.set(cache_key, result)
                return {**result, "_cache": "miss"}
            if resp.status_code == 429:
                return _empty_hash_result(file_hash, "rate_limited")
            if resp.status_code != 200:
                return _empty_hash_result(file_hash, f"http_{resp.status_code}")
            attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        threat_info = attrs.get("popular_threat_classification", {})
        result = {
            "hash": file_hash, "malicious_count": malicious, "total_engines": total,
            "detection_rate": round(malicious / total, 3) if total > 0 else 0,
            "threat_label": threat_info.get("suggested_threat_label"),
            "threat_category": (threat_info.get("popular_threat_category", [{}])[0].get("value")
                if threat_info.get("popular_threat_category") else None),
            "file_type": attrs.get("type_description"), "file_size": attrs.get("size"),
            "tags": attrs.get("tags", [])[:10], "source": "virustotal", "_cache": "miss",
        }
        await cache.set(cache_key, result)
        return result
    except httpx.HTTPError as e:
        return _empty_hash_result(file_hash, f"connection_error: {e}")


async def lookup_ip_virustotal(ip: str) -> Dict[str, Any]:
    cache = get_cache()
    cache_key = f"vt:ip:{ip}"
    cached = await cache.get(cache_key)
    if cached:
        return {**cached, "_cache": "hit"}
    if not settings.virustotal_api_key:
        return {"ip": ip, "source": "virustotal", "error": "no_api_key", "_cache": "miss"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": settings.virustotal_api_key},
            )
            if resp.status_code != 200:
                return {"ip": ip, "source": "virustotal", "error": f"http_{resp.status_code}"}
            attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result = {
            "ip": ip, "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "country": attrs.get("country"), "as_owner": attrs.get("as_owner"),
            "reputation": attrs.get("reputation", 0), "source": "virustotal", "_cache": "miss",
        }
        await cache.set(cache_key, result)
        return result
    except httpx.HTTPError as e:
        return {"ip": ip, "source": "virustotal", "error": str(e)}


async def lookup_domain_virustotal(domain: str) -> Dict[str, Any]:
    cache = get_cache()
    cache_key = f"vt:domain:{domain}"
    cached = await cache.get(cache_key)
    if cached:
        return {**cached, "_cache": "hit"}
    if not settings.virustotal_api_key:
        return {"domain": domain, "source": "virustotal", "error": "no_api_key"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": settings.virustotal_api_key},
            )
            if resp.status_code != 200:
                return {"domain": domain, "source": "virustotal", "error": f"http_{resp.status_code}"}
            attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result = {
            "domain": domain, "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "registrar": attrs.get("registrar"), "reputation": attrs.get("reputation", 0),
            "categories": attrs.get("categories", {}), "source": "virustotal", "_cache": "miss",
        }
        await cache.set(cache_key, result)
        return result
    except httpx.HTTPError as e:
        return {"domain": domain, "source": "virustotal", "error": str(e)}


async def lookup_all_iocs(indicators: Dict[str, list]) -> Dict[str, Any]:
    results = {"ips": {}, "hashes": {}, "domains": {}}
    total_lookups = cache_hits = malicious_found = 0
    for ip in indicators.get("ips", []):
        if _is_private_ip(ip):
            results["ips"][ip] = {"ip": ip, "source": "internal", "abuse_score": 0, "note": "private_ip"}
            continue
        total_lookups += 1
        result = await lookup_ip_abuseipdb(ip)
        if result.get("_cache") == "hit": cache_hits += 1
        if (result.get("abuse_score") or 0) >= 50: malicious_found += 1
        results["ips"][ip] = result
    all_hashes = indicators.get("hashes_sha256", []) + indicators.get("hashes_md5", []) + indicators.get("hashes_sha1", [])
    for h in all_hashes:
        total_lookups += 1
        result = await lookup_hash_virustotal(h)
        if result.get("_cache") == "hit": cache_hits += 1
        if (result.get("malicious_count") or 0) >= 5: malicious_found += 1
        results["hashes"][h] = result
    for domain in indicators.get("domains", []):
        if _is_benign_domain(domain): continue
        total_lookups += 1
        result = await lookup_domain_virustotal(domain)
        if result.get("_cache") == "hit": cache_hits += 1
        if (result.get("malicious_count") or 0) >= 3: malicious_found += 1
        results["domains"][domain] = result
    results["summary"] = {
        "total_lookups": total_lookups, "cache_hits": cache_hits,
        "cache_hit_rate": round(cache_hits / total_lookups, 2) if total_lookups > 0 else 0,
        "malicious_found": malicious_found,
    }
    return results


def _is_private_ip(ip: str) -> bool:
    return (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.")
        or ip == "0.0.0.0" or any(ip.startswith(f"172.{i}.") for i in range(16, 32)))

def _is_benign_domain(domain: str) -> bool:
    safe = ("microsoft.com", "google.com", "googleapis.com", "amazon.com",
        "cloudflare.com", "github.com", "ubuntu.com", "windows.net",
        "office.com", "office365.com", "outlook.com", "windowsupdate.com")
    return any(domain.endswith(s) for s in safe)

def _empty_ip_result(ip, source, error):
    return {"ip": ip, "abuse_score": None, "country": None, "isp": None,
        "total_reports": None, "is_tor": None, "source": source, "error": error, "_cache": "miss"}

def _empty_hash_result(file_hash, error):
    return {"hash": file_hash, "malicious_count": None, "total_engines": None,
        "detection_rate": None, "threat_label": None, "source": "virustotal", "error": error, "_cache": "miss"}