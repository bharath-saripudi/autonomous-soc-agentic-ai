"""Enrichment Agent — IOC extraction and threat intelligence lookups.

Second agent in the pipeline (after Triage). Extracts all Indicators
of Compromise (IPs, hashes, domains) from the alert and runs them
through threat intelligence APIs (VirusTotal, AbuseIPDB) with Redis
caching to minimize API costs.

Reads:  normalized, raw_data, triage_score
Writes: ioc_list, enrichment_results, next_agent
"""

import time
from typing import Any, Dict, List

import structlog

from src.state import AgentState
from src.ingestion.normalizer import AlertNormalizer
from src.services.threat_intel import lookup_all_iocs
from src.services.audit import log_audit

logger = structlog.get_logger()
normalizer = AlertNormalizer()


async def enrichment_agent(state: AgentState) -> AgentState:
    """Extract IOCs from alert and enrich with threat intelligence.

    Reads:  normalized, raw_data
    Writes: ioc_list, enrichment_results, next_agent
    """
    start_time = time.time()
    alert_id = state["alert_id"]

    logger.info("enrichment_started", alert_id=alert_id)

    try:
        # ── Step 1: Extract IOCs ─────────────────────────────────
        # Pull indicators from normalized data first, fall back to raw
        normalized = state.get("normalized") or {}
        raw_data = state.get("raw_data") or {}

        # Get pre-extracted indicators from normalizer
        indicators = normalized.get("indicators", {})

        # If normalizer didn't extract, do it now from raw data
        if not any(indicators.get(k) for k in ["ips", "hashes_sha256", "hashes_md5", "domains"]):
            full_text = str(raw_data)
            indicators = normalizer._extract_iocs(full_text)

        # Also pull explicit fields from the alert
        indicators = _merge_explicit_iocs(indicators, normalized, raw_data)

        state["ioc_list"] = indicators

        ioc_count = sum(len(v) for v in indicators.values() if isinstance(v, list))
        logger.info("iocs_extracted", alert_id=alert_id, total_iocs=ioc_count, breakdown={
            k: len(v) for k, v in indicators.items() if isinstance(v, list) and v
        })

        # ── Step 2: Run Threat Intel Lookups ─────────────────────
        if ioc_count > 0:
            enrichment_results = await lookup_all_iocs(indicators)
        else:
            enrichment_results = {
                "ips": {},
                "hashes": {},
                "domains": {},
                "summary": {
                    "total_lookups": 0,
                    "cache_hits": 0,
                    "cache_hit_rate": 0,
                    "malicious_found": 0,
                },
            }

        state["enrichment_results"] = enrichment_results

        # ── Step 3: Assess enrichment findings ───────────────────
        summary = enrichment_results.get("summary", {})
        malicious_found = summary.get("malicious_found", 0)

        # If enrichment found malicious IOCs, bump severity context
        if malicious_found > 0 and state.get("triage_score", 0) < 0.70:
            logger.info(
                "enrichment_severity_boost",
                alert_id=alert_id,
                malicious_found=malicious_found,
                original_score=state.get("triage_score"),
            )

        # ── Step 4: Route to next agent ──────────────────────────
        state["next_agent"] = "hunting"

        latency = round(time.time() - start_time, 2)

        # Audit log
        await log_audit(
            alert_id=alert_id,
            agent="enrichment",
            action="iocs_enriched",
            details={
                "ioc_count": ioc_count,
                "total_lookups": summary.get("total_lookups", 0),
                "cache_hits": summary.get("cache_hits", 0),
                "cache_hit_rate": summary.get("cache_hit_rate", 0),
                "malicious_found": malicious_found,
                "latency_sec": latency,
            },
        )

        logger.info(
            "enrichment_complete",
            alert_id=alert_id,
            ioc_count=ioc_count,
            lookups=summary.get("total_lookups", 0),
            cache_hits=summary.get("cache_hits", 0),
            malicious=malicious_found,
            latency_sec=latency,
        )

    except Exception as e:
        logger.error("enrichment_error", alert_id=alert_id, error=str(e))
        state["enrichment_results"] = {"error": str(e)}
        state["next_agent"] = "hunting"  # Continue pipeline even on error
        state["error"] = f"Enrichment error: {e}"

        await log_audit(
            alert_id=alert_id,
            agent="enrichment",
            action="enrichment_failed",
            details={"error": str(e)},
        )

    return state


def _merge_explicit_iocs(
    indicators: Dict[str, List],
    normalized: Dict[str, Any],
    raw_data: Dict[str, Any],
) -> Dict[str, List]:
    """Merge IOCs from regex extraction with explicit alert fields.

    Some alerts have IPs/hashes in named fields (src_ip, hash_sha256)
    that regex might miss or that we want to ensure are included.
    """
    # Collect IPs from explicit fields
    explicit_ips = []
    for field in ["source_ip", "src_ip", "dest_ip", "dst_ip"]:
        ip = normalized.get(field) or raw_data.get(field)
        if ip and isinstance(ip, str):
            explicit_ips.append(ip)

    # Handle src_ips as a list (e.g., credential stuffing alerts)
    for field in ["src_ips", "source_ips"]:
        ip_list = raw_data.get(field, [])
        if isinstance(ip_list, list):
            explicit_ips.extend(ip_list)

    # Merge without duplicates
    existing_ips = set(indicators.get("ips", []))
    for ip in explicit_ips:
        if ip not in existing_ips:
            indicators.setdefault("ips", []).append(ip)
            existing_ips.add(ip)

    # Collect hashes from explicit fields
    for field in ["hash_sha256", "sha256", "file_hash"]:
        h = raw_data.get(field)
        if h and isinstance(h, str) and len(h) == 64:
            if h not in indicators.get("hashes_sha256", []):
                indicators.setdefault("hashes_sha256", []).append(h)

    for field in ["hash_md5", "md5"]:
        h = raw_data.get(field)
        if h and isinstance(h, str) and len(h) == 32:
            if h not in indicators.get("hashes_md5", []):
                indicators.setdefault("hashes_md5", []).append(h)

    # Collect domains from explicit fields
    for field in ["domain", "dst_domain", "dest_domain"]:
        d = raw_data.get(field)
        if d and isinstance(d, str):
            if d not in indicators.get("domains", []):
                indicators.setdefault("domains", []).append(d)

    return indicators