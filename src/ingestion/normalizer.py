"""Normalize diverse alert formats into a unified internal schema.

Supports:
  - Raw JSON (modern tools, APIs)
  - Syslog (RFC 3164 / 5424)
  - CEF (ArcSight Common Event Format)
  - LEEF (IBM QRadar Log Event Extended Format)
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional


class AlertNormalizer:
    """Translates incoming alert formats into a unified schema."""

    def normalize(self, source: str, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Route to the correct parser based on source/content detection."""
        message = str(raw.get("message", ""))

        if "CEF:" in message:
            parsed = self._parse_cef(raw)
        elif "LEEF:" in message:
            parsed = self._parse_leef(raw)
        elif source == "syslog":
            parsed = self._parse_syslog(raw)
        else:
            parsed = self._parse_json(raw)

        # Always extract IOCs from the full raw data
        full_text = str(raw)
        parsed["indicators"] = self._extract_iocs(full_text)
        parsed["raw_reference"] = raw

        return parsed

    # ── Format Parsers ──────────────────────────────────────────

    def _parse_json(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Parse modern JSON-formatted alerts."""
        return {
            "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
            "source_ip": raw.get("src_ip") or raw.get("source_ip"),
            "dest_ip": raw.get("dst_ip") or raw.get("dest_ip"),
            "source_port": raw.get("src_port") or raw.get("source_port"),
            "dest_port": raw.get("dst_port") or raw.get("dest_port"),
            "protocol": raw.get("protocol"),
            "hostname": raw.get("hostname") or raw.get("host"),
            "username": raw.get("username") or raw.get("user"),
            "event_type": raw.get("event_type") or raw.get("type"),
            "severity_hint": raw.get("severity") or raw.get("priority"),
            "description": raw.get("message") or raw.get("description", ""),
            "process": raw.get("process") or raw.get("process_name"),
            "pid": raw.get("pid") or raw.get("process_id"),
        }

    def _parse_syslog(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Parse syslog messages (RFC 3164 / 5424)."""
        message = raw.get("message", "")

        # Try RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
        rfc5424 = re.match(
            r"<(\d+)>\d*\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)",
            message,
        )
        if rfc5424:
            return {
                "timestamp": rfc5424.group(2),
                "hostname": rfc5424.group(3),
                "event_type": rfc5424.group(4),
                "severity_hint": self._syslog_severity(int(rfc5424.group(1))),
                "description": rfc5424.group(7),
                "source_ip": None,
                "dest_ip": None,
                "source_port": None,
                "dest_port": None,
                "protocol": None,
                "username": None,
                "process": rfc5424.group(4),
                "pid": rfc5424.group(5) if rfc5424.group(5) != "-" else None,
            }

        # Fallback: treat entire message as description
        return {
            "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
            "hostname": raw.get("hostname"),
            "event_type": "syslog",
            "severity_hint": raw.get("severity"),
            "description": message,
            "source_ip": None,
            "dest_ip": None,
            "source_port": None,
            "dest_port": None,
            "protocol": None,
            "username": None,
            "process": None,
            "pid": None,
        }

    def _parse_cef(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Parse ArcSight Common Event Format.
        Format: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
        """
        message = raw.get("message", "")
        parts = message.split("|", 7)

        extension = {}
        if len(parts) > 7:
            # Parse key=value pairs from extension
            extension = self._parse_kv_pairs(parts[7])

        return {
            "timestamp": extension.get("rt", datetime.utcnow().isoformat()),
            "source_ip": extension.get("src"),
            "dest_ip": extension.get("dst"),
            "source_port": extension.get("spt"),
            "dest_port": extension.get("dpt"),
            "protocol": extension.get("proto"),
            "hostname": extension.get("dhost") or extension.get("shost"),
            "username": extension.get("duser") or extension.get("suser"),
            "event_type": parts[5] if len(parts) > 5 else "unknown",
            "severity_hint": parts[6] if len(parts) > 6 else None,
            "description": parts[5] if len(parts) > 5 else message,
            "process": extension.get("dproc") or extension.get("sproc"),
            "pid": extension.get("dpid") or extension.get("spid"),
        }

    def _parse_leef(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Parse IBM QRadar LEEF format.
        Format: LEEF:Version|Vendor|Product|Version|EventID|Extension
        """
        message = raw.get("message", "")
        parts = message.split("|", 5)

        extension = {}
        if len(parts) > 5:
            extension = self._parse_kv_pairs(parts[5], delimiter="\t")

        return {
            "timestamp": extension.get("devTime", datetime.utcnow().isoformat()),
            "source_ip": extension.get("src"),
            "dest_ip": extension.get("dst"),
            "source_port": extension.get("srcPort"),
            "dest_port": extension.get("dstPort"),
            "protocol": extension.get("proto"),
            "hostname": extension.get("dstName") or extension.get("srcName"),
            "username": extension.get("usrName"),
            "event_type": parts[4] if len(parts) > 4 else "unknown",
            "severity_hint": extension.get("sev"),
            "description": extension.get("msg", ""),
            "process": None,
            "pid": None,
        }

    # ── IOC Extraction ──────────────────────────────────────────

    @staticmethod
    def _extract_iocs(text: str) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise from alert text."""
        # IPv4 addresses (exclude obvious private/localhost for threat lookups)
        ips = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))

        # MD5 hashes (32 hex chars)
        hashes_md5 = list(set(re.findall(r"\b[a-fA-F0-9]{32}\b", text)))

        # SHA256 hashes (64 hex chars)
        hashes_sha256 = list(set(re.findall(r"\b[a-fA-F0-9]{64}\b", text)))

        # SHA1 hashes (40 hex chars)
        hashes_sha1 = list(set(re.findall(r"\b[a-fA-F0-9]{40}\b", text)))

        # Domain names (basic pattern, exclude common false positives)
        domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|ru|cn|info|biz|top|tk|ml)\b"
        domains = list(set(re.findall(domain_pattern, text)))

        # URLs
        urls = list(set(re.findall(r"https?://[^\s\"'<>]+", text)))

        # Email addresses
        emails = list(set(re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text)))

        return {
            "ips": ips,
            "hashes_md5": hashes_md5,
            "hashes_sha256": hashes_sha256,
            "hashes_sha1": hashes_sha1,
            "domains": domains,
            "urls": urls,
            "emails": emails,
        }

    # ── Helpers ──────────────────────────────────────────────────

    @staticmethod
    def _parse_kv_pairs(text: str, delimiter: str = " ") -> Dict[str, str]:
        """Parse key=value pairs from CEF/LEEF extension fields."""
        result = {}
        for pair in text.split(delimiter):
            if "=" in pair:
                key, _, value = pair.partition("=")
                result[key.strip()] = value.strip()
        return result

    @staticmethod
    def _syslog_severity(priority: int) -> str:
        """Map syslog PRI to human-readable severity."""
        severity = priority % 8
        severity_map = {
            0: "emergency",
            1: "alert",
            2: "critical",
            3: "error",
            4: "warning",
            5: "notice",
            6: "informational",
            7: "debug",
        }
        return severity_map.get(severity, "unknown")