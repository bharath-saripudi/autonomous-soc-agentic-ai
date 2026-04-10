"""Feature Engineering — Convert raw alert data into ML-ready feature vectors.

Extracts 25+ features from normalized alert data including:
  - Statistical: port numbers, byte counts, connection counts
  - Categorical: event type, source, protocol (one-hot encoded)
  - Temporal: hour of day, day of week, is_weekend
  - Network: IP entropy, private/public IP flags, known-bad port flags
  - Text: description length, keyword presence scores
"""

import re
import math
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np


# ── Known suspicious indicators ──
SUSPICIOUS_PORTS = {22, 23, 445, 3389, 4444, 5555, 8080, 8443, 1337, 31337}
SUSPICIOUS_KEYWORDS = [
    "brute", "injection", "malware", "ransomware", "exfiltration",
    "beacon", "c2", "command and control", "lateral", "privilege",
    "mimikatz", "powershell", "encoded", "reverse shell", "exploit",
    "phishing", "credential", "dump", "golden ticket", "backdoor",
    "encryption", "decrypt", "ransom", "tunneling", "suspicious",
]
BENIGN_KEYWORDS = [
    "update", "patch", "scheduled", "backup", "routine",
    "maintenance", "heartbeat", "health check", "normal",
]

EVENT_TYPES = [
    "ssh_auth_failure", "ssh_brute_force", "ssh_auth_success",
    "suspicious_download", "mass_file_encryption", "dns_tunneling",
    "c2_beacon", "credential_dump", "privilege_escalation",
    "lateral_movement", "spearphishing", "macro_execution",
    "data_exfiltration", "port_scan", "sql_injection",
    "xss_attempt", "web_attack", "malware_download",
    "account_lockout", "unauthorized_access", "policy_violation",
    "network_anomaly", "other",
]

SOURCES = ["firewall", "ids", "edr", "ndr", "proxy", "dns", "email",
           "dlp", "ad", "syslog", "waf", "api", "other"]


def extract_features(normalized: Dict[str, Any], raw_data: Dict[str, Any]) -> np.ndarray:
    """Extract a fixed-length feature vector from alert data.

    Returns: numpy array of shape (n_features,) — currently 65 features.
    """
    features = []

    # ── 1. Numeric fields (7) ──
    features.append(_safe_float(raw_data.get("count") or normalized.get("count"), 0))
    features.append(_safe_float(raw_data.get("bytes_transferred"), 0))
    features.append(_safe_float(raw_data.get("files_affected"), 0))
    features.append(_safe_float(raw_data.get("query_count"), 0))
    features.append(_safe_float(raw_data.get("duration_sec"), 0))
    features.append(_safe_float(raw_data.get("interval_sec"), 0))
    features.append(_safe_float(raw_data.get("pid") or raw_data.get("port"), 0))

    # ── 2. Event type one-hot (23) ──
    event_type = (normalized.get("event_type") or raw_data.get("event_type", "other")).lower()
    for et in EVENT_TYPES:
        features.append(1.0 if et in event_type else 0.0)

    # ── 3. Source one-hot (13) ──
    source = (normalized.get("source") or raw_data.get("source", "other")).lower()
    for s in SOURCES:
        features.append(1.0 if s in source else 0.0)

    # ── 4. Network features (6) ──
    src_ip = normalized.get("source_ip") or raw_data.get("src_ip", "")
    dest_ip = normalized.get("dest_ip") or raw_data.get("dest_ip", "")
    features.append(1.0 if _is_private_ip(src_ip) else 0.0)
    features.append(1.0 if _is_private_ip(dest_ip) else 0.0)
    features.append(_ip_entropy(src_ip))
    features.append(_ip_entropy(dest_ip))
    port = _safe_float(raw_data.get("dest_port") or raw_data.get("port"), 0)
    features.append(port)
    features.append(1.0 if int(port) in SUSPICIOUS_PORTS else 0.0)

    # ── 5. Temporal features (4) ──
    timestamp = normalized.get("timestamp") or raw_data.get("timestamp")
    dt = _parse_timestamp(timestamp) if timestamp else datetime.utcnow()
    features.append(dt.hour / 23.0)  # Normalized hour
    features.append(dt.weekday() / 6.0)  # Normalized day
    features.append(1.0 if dt.weekday() >= 5 else 0.0)  # Is weekend
    features.append(1.0 if dt.hour < 6 or dt.hour > 22 else 0.0)  # Off hours

    # ── 6. Text features (8) ──
    description = (normalized.get("description") or raw_data.get("message", "")).lower()
    features.append(len(description) / 500.0)  # Normalized length

    # Suspicious keyword count
    susp_score = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in description)
    features.append(min(susp_score / 5.0, 1.0))

    # Benign keyword count
    benign_score = sum(1 for kw in BENIGN_KEYWORDS if kw in description)
    features.append(min(benign_score / 3.0, 1.0))

    # Has IP pattern in description
    features.append(1.0 if re.search(r'\d+\.\d+\.\d+\.\d+', description) else 0.0)

    # Has hash in description
    features.append(1.0 if re.search(r'[a-f0-9]{32,}', description) else 0.0)

    # Has URL in description
    features.append(1.0 if re.search(r'https?://', description) else 0.0)

    # Has MITRE technique reference
    features.append(1.0 if re.search(r'T\d{4}', str(raw_data)) else 0.0)

    # Number of unique IOC types present
    indicators = normalized.get("indicators", {})
    ioc_types = sum(1 for v in indicators.values() if isinstance(v, list) and len(v) > 0)
    features.append(ioc_types / 5.0)

    # ── 7. Alert complexity (4) ──
    features.append(len(str(raw_data)) / 2000.0)  # Raw data size
    features.append(len(raw_data.keys()) / 15.0)  # Number of fields
    hostname = raw_data.get("hostname", "")
    features.append(1.0 if any(x in hostname.lower() for x in ["dc-", "srv-", "fs-"]) else 0.0)  # Is server
    features.append(1.0 if raw_data.get("technique") or raw_data.get("mitre") else 0.0)  # Has MITRE

    return np.array(features, dtype=np.float64)


def get_feature_names() -> List[str]:
    """Return human-readable feature names matching extract_features output."""
    names = [
        "count", "bytes_transferred", "files_affected",
        "query_count", "duration_sec", "interval_sec", "pid_or_port",
    ]
    names += [f"event_{et}" for et in EVENT_TYPES]
    names += [f"source_{s}" for s in SOURCES]
    names += [
        "src_ip_private", "dest_ip_private", "src_ip_entropy", "dest_ip_entropy",
        "dest_port", "suspicious_port",
    ]
    names += ["hour_norm", "weekday_norm", "is_weekend", "off_hours"]
    names += [
        "desc_length", "suspicious_keyword_score", "benign_keyword_score",
        "has_ip_pattern", "has_hash", "has_url", "has_mitre_ref", "ioc_type_count",
    ]
    names += ["raw_data_size", "field_count", "is_server_target", "has_mitre_technique"]
    return names


# ── Helpers ──

def _safe_float(val, default=0.0) -> float:
    try:
        return float(val) if val is not None else default
    except (ValueError, TypeError):
        return default


def _is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    return (ip.startswith("10.") or ip.startswith("192.168.") or
            ip.startswith("127.") or ip == "0.0.0.0" or
            any(ip.startswith(f"172.{i}.") for i in range(16, 32)))


def _ip_entropy(ip: str) -> float:
    """Shannon entropy of IP address string — higher = more random."""
    if not ip:
        return 0.0
    freq = {}
    for c in ip:
        freq[c] = freq.get(c, 0) + 1
    length = len(ip)
    entropy = -sum((count/length) * math.log2(count/length)
                    for count in freq.values())
    return entropy / 4.0  # Normalize to ~0-1


def _parse_timestamp(ts) -> datetime:
    if isinstance(ts, datetime):
        return ts
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts)
    for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]:
        try:
            return datetime.strptime(str(ts), fmt)
        except (ValueError, TypeError):
            continue
    return datetime.utcnow()