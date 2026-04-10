import React, { useState, useEffect } from "react";
import SeverityBadge from "../components/SeverityBadge";
import TimelineView from "../components/TimelineView";

const API_BASE = "http://localhost:8000";

export default function AlertDetail({ alertId, onBack }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDetail = async () => {
      try {
        const res = await fetch(`${API_BASE}/alerts/${alertId}`);
        if (res.ok) setData(await res.json());
      } catch (e) { console.error(e); }
      setLoading(false);
    };
    fetchDetail();
  }, [alertId]);

  if (loading) return <div style={{ padding: 40, textAlign: "center", color: "#8492a6", fontFamily: "'JetBrains Mono'" }}>Loading alert details...</div>;
  if (!data) return <div style={{ padding: 40, textAlign: "center", color: "#ef4444", fontFamily: "'JetBrains Mono'" }}>Alert not found</div>;

  const alert = data.alert;
  const score = alert.triage_score || 0;
  const sev = score >= 0.9 ? "critical" : score >= 0.7 ? "high" : score >= 0.4 ? "medium" : score >= 0.16 ? "low" : "info";

  return (
    <div>
      <button onClick={onBack} style={{ background: "none", border: "1px solid #1e293b", color: "#3b82f6", padding: "6px 14px", borderRadius: 4, fontFamily: "'JetBrains Mono'", fontSize: 11, cursor: "pointer", marginBottom: 20 }}>← BACK TO FEED</button>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        {/* Left: Alert Info */}
        <div>
          <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 20, marginBottom: 16 }}>
            <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#4a5568", letterSpacing: 1, marginBottom: 12 }}>ALERT OVERVIEW</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <div style={{ padding: 12, background: "#0a0e17", borderRadius: 6 }}>
                <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 9, color: "#8492a6", marginBottom: 4 }}>SEVERITY</div>
                <SeverityBadge severity={sev} />
              </div>
              <div style={{ padding: 12, background: "#0a0e17", borderRadius: 6 }}>
                <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 9, color: "#8492a6", marginBottom: 4 }}>SCORE</div>
                <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 22, fontWeight: 700, color: { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#6b7280" }[sev] }}>{score.toFixed(2)}</div>
              </div>
              <div style={{ padding: 12, background: "#0a0e17", borderRadius: 6 }}>
                <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 9, color: "#8492a6", marginBottom: 4 }}>CONFIDENCE</div>
                <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 22, fontWeight: 700, color: (alert.confidence || 0) > 0.85 ? "#10b981" : "#eab308" }}>{(alert.confidence || 0).toFixed(2)}</div>
              </div>
              <div style={{ padding: 12, background: "#0a0e17", borderRadius: 6 }}>
                <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 9, color: "#8492a6", marginBottom: 4 }}>STATUS</div>
                <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 12, fontWeight: 600, color: "#e2e8f0" }}>{(alert.status || "—").toUpperCase()}</div>
              </div>
            </div>
          </div>

          {/* Triage Reasoning */}
          {alert.triage_reasoning && (
            <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 20, marginBottom: 16 }}>
              <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#4a5568", letterSpacing: 1, marginBottom: 10 }}>AI TRIAGE REASONING</div>
              <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: "#e2e8f0", lineHeight: 1.6, whiteSpace: "pre-wrap" }}>{alert.triage_reasoning}</div>
            </div>
          )}

          {/* Raw Data */}
          <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 20 }}>
            <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#4a5568", letterSpacing: 1, marginBottom: 10 }}>RAW DATA</div>
            <pre style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#8492a6", whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 300, overflowY: "auto" }}>{JSON.stringify(data.raw_data, null, 2)}</pre>
          </div>
        </div>

        {/* Right: Timeline + Enrichment */}
        <div>
          {/* Agent Pipeline Timeline */}
          <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 20, marginBottom: 16 }}>
            <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#4a5568", letterSpacing: 1, marginBottom: 12 }}>AGENT PIPELINE TRACE</div>
            <TimelineView auditTrail={data.audit_trail || []} />
          </div>

          {/* Enrichment Results */}
          {alert.enrichment_results && (
            <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 20, marginBottom: 16 }}>
              <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#4a5568", letterSpacing: 1, marginBottom: 10 }}>ENRICHMENT RESULTS</div>
              <pre style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#8492a6", whiteSpace: "pre-wrap", maxHeight: 200, overflowY: "auto" }}>{JSON.stringify(alert.enrichment_results, null, 2)}</pre>
            </div>
          )}

          {/* Actions Taken */}
          {alert.actions_taken && alert.actions_taken.length > 0 && (
            <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 20 }}>
              <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#4a5568", letterSpacing: 1, marginBottom: 10 }}>ACTIONS TAKEN</div>
              {alert.actions_taken.map((action, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 0", borderBottom: i < alert.actions_taken.length - 1 ? "1px solid #1e293b08" : "none" }}>
                  <span style={{ fontSize: 10, color: action.status === "executed" ? "#10b981" : action.status === "blocked" ? "#ef4444" : "#eab308" }}>
                    {action.status === "executed" ? "✓" : action.status === "blocked" ? "✕" : "⊘"}
                  </span>
                  <span style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: "#e2e8f0" }}>{action.action?.replace("_", " ").toUpperCase()}</span>
                  <span style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#8492a6", marginLeft: "auto" }}>{action.target}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
