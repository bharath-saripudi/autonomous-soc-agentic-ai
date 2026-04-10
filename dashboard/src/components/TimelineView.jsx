import React from "react";

const agentColors = {
  orchestrator: "#3b82f6", ingestion: "#8492a6", triage: "#8b5cf6",
  enrichment: "#f97316", hunting: "#eab308", response: "#10b981",
  learning: "#22c55e", analyst: "#3b82f6",
};

export default function TimelineView({ auditTrail = [] }) {
  if (auditTrail.length === 0) {
    return <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: "#4a5568", padding: 12 }}>No audit trail available</div>;
  }

  return (
    <div>
      {auditTrail.map((entry, i) => {
        const color = agentColors[entry.agent] || "#8492a6";
        const time = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : "";
        return (
          <div key={i} style={{ display: "flex", gap: 12, position: "relative", paddingBottom: i < auditTrail.length - 1 ? 16 : 0 }}>
            {/* Timeline line */}
            {i < auditTrail.length - 1 && (
              <div style={{ position: "absolute", left: 11, top: 20, bottom: 0, width: 1, background: "#1e293b" }} />
            )}
            {/* Dot */}
            <div style={{ width: 22, minWidth: 22, height: 22, borderRadius: "50%", background: `${color}22`, border: `2px solid ${color}`, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1 }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: color }} />
            </div>
            {/* Content */}
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, fontWeight: 600, color, textTransform: "uppercase" }}>{entry.agent}</span>
                <span style={{ fontFamily: "'JetBrains Mono'", fontSize: 9, color: "#4a5568" }}>{time}</span>
              </div>
              <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: "#e2e8f0", marginTop: 2 }}>{entry.action?.replace(/_/g, " ")}</div>
              {entry.details && (
                <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 9, color: "#8492a6", marginTop: 4, padding: "4px 8px", background: "#0a0e17", borderRadius: 4, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                  {typeof entry.details === "object" ? Object.entries(entry.details).map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join(" · ") : String(entry.details)}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
