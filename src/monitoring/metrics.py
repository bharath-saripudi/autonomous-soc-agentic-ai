"""Pipeline Metrics — Prometheus-compatible monitoring for the SOC.

Tracks:
  - Alert ingestion/processing/failure counts
  - Severity distribution
  - Action execution counts (block, isolate, kill, notify)
  - Auto-closed and escalated counts
  - False positive rate
  - Average processing time

Export formats:
  - .to_dict()       → JSON for /stats/pipeline endpoint
  - .to_prometheus()  → Prometheus text exposition for /metrics endpoint
"""

from typing import Dict, Any


class PipelineMetrics:
    """In-memory pipeline performance counters."""

    def __init__(self):
        self.alerts_ingested = 0
        self.alerts_processed = 0
        self.alerts_failed = 0
        self.total_processing_time = 0.0
        self.severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self.action_counts = {"block_ip": 0, "isolate_host": 0, "kill_process": 0, "notify": 0}
        self.auto_closed = 0
        self.escalated = 0
        self.false_positives = 0

    def record_ingestion(self):
        """Called when a new alert is received."""
        self.alerts_ingested += 1

    def record_completion(self, state: dict, processing_time: float):
        """Called when an alert finishes the full pipeline."""
        self.alerts_processed += 1
        self.total_processing_time += processing_time

        score = state.get("triage_score", 0)
        if score >= 0.90:
            self.severity_counts["critical"] += 1
        elif score >= 0.70:
            self.severity_counts["high"] += 1
        elif score >= 0.40:
            self.severity_counts["medium"] += 1
        elif score >= 0.16:
            self.severity_counts["low"] += 1
        else:
            self.severity_counts["info"] += 1

        status = state.get("response_status", "")
        if status == "closed":
            self.auto_closed += 1
        elif status == "escalated":
            self.escalated += 1

        if score <= 0.15:
            self.false_positives += 1

        for action in state.get("actions_taken") or []:
            action_type = action.get("action", "")
            if action_type in self.action_counts and action.get("status") == "executed":
                self.action_counts[action_type] += 1

    def record_failure(self):
        """Called when pipeline processing fails."""
        self.alerts_failed += 1

    @property
    def avg_processing_time(self) -> float:
        if self.alerts_processed == 0:
            return 0
        return round(self.total_processing_time / self.alerts_processed, 2)

    def to_dict(self) -> Dict[str, Any]:
        """Export as JSON-friendly dict for API responses."""
        return {
            "alerts_ingested": self.alerts_ingested,
            "alerts_processed": self.alerts_processed,
            "alerts_failed": self.alerts_failed,
            "avg_processing_time_sec": self.avg_processing_time,
            "severity_counts": self.severity_counts,
            "action_counts": self.action_counts,
            "auto_closed": self.auto_closed,
            "escalated": self.escalated,
            "false_positives": self.false_positives,
        }

    def to_prometheus(self) -> str:
        """Export in Prometheus text exposition format."""
        lines = [
            "# HELP soc_alerts_ingested_total Total alerts ingested",
            "# TYPE soc_alerts_ingested_total counter",
            f"soc_alerts_ingested_total {self.alerts_ingested}",
            "",
            "# HELP soc_alerts_processed_total Total alerts fully processed",
            "# TYPE soc_alerts_processed_total counter",
            f"soc_alerts_processed_total {self.alerts_processed}",
            "",
            "# HELP soc_alerts_failed_total Total alerts that failed processing",
            "# TYPE soc_alerts_failed_total counter",
            f"soc_alerts_failed_total {self.alerts_failed}",
            "",
            "# HELP soc_processing_time_avg_seconds Average pipeline processing time",
            "# TYPE soc_processing_time_avg_seconds gauge",
            f"soc_processing_time_avg_seconds {self.avg_processing_time}",
            "",
            "# HELP soc_alerts_by_severity Alerts by severity level",
            "# TYPE soc_alerts_by_severity gauge",
        ]
        for level, count in self.severity_counts.items():
            lines.append(f'soc_alerts_by_severity{{level="{level}"}} {count}')

        lines.extend([
            "",
            "# HELP soc_actions_executed_total Actions executed by type",
            "# TYPE soc_actions_executed_total counter",
        ])
        for action, count in self.action_counts.items():
            lines.append(f'soc_actions_executed_total{{action="{action}"}} {count}')

        lines.extend([
            "",
            "# HELP soc_auto_closed_total Alerts auto-closed as benign",
            "# TYPE soc_auto_closed_total counter",
            f"soc_auto_closed_total {self.auto_closed}",
            "",
            "# HELP soc_escalated_total Alerts escalated to humans",
            "# TYPE soc_escalated_total counter",
            f"soc_escalated_total {self.escalated}",
            "",
            "# HELP soc_false_positives_total Alerts identified as false positives",
            "# TYPE soc_false_positives_total counter",
            f"soc_false_positives_total {self.false_positives}",
        ])

        return "\n".join(lines) + "\n"


# Singleton instance
_metrics = None


def get_metrics() -> PipelineMetrics:
    """Get the global metrics singleton."""
    global _metrics
    if _metrics is None:
        _metrics = PipelineMetrics()
    return _metrics