import React, { useState, useEffect } from "react";

const API_BASE = "http://localhost:8000";

export default function Statistics() {
  const [overview, setOverview] = useState({});
  const [pipeline, setPipeline] = useState({});

  useEffect(() => {
    Promise.all([
      fetch(`${API_BASE}/stats/overview`).then(r => r.ok ? r.json() : {}).catch(() => ({})),
      fetch(`${API_BASE}/stats/pipeline`).then(r => r.ok ? r.json() : {}).catch(() => ({})),
    ]).then(([o, p]) => { setOverview(o); setPipeline(p); });
  }, []);

  const sevDist = overview.severity_distribution || pipeline.severity_counts || {};
  const actions = pipeline.action_counts || {};
  const processed = pipeline.alerts_processed || 1;
  const sevColors = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#6b7280" };

  return (
    <div>
      {/* Performance Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
        {[
          { label: "Success Rate", value: `${((pipeline.alerts_processed || 0) / (pipeline.alerts_ingested || 1) * 100).toFixed(1)}%`, color: "#10b981" },
          { label: "False Positive Rate", value: `${((pipeline.false_positives || 0) / processed * 100).toFixed(1)}%`, color: "#eab308" },
          { label: "Automation Rate", value: `${((pipeline.auto_closed || 0) / processed * 100).toFixed(0)}%`, color: "#3b82f6" },
          { label: "Escalation Rate", value: `${((pipeline.escalated || 0) / processed * 100).toFixed(1)}%`, color: "#ef4444" },
        ].map(item => (
          <div key={item.label} style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 20, position: "relative", overflow: "hidden" }}>
            <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${item.color}, transparent)`, opacity: 0.5 }} />
            <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 9, color: "#8492a6", letterSpacing: 1, marginBottom: 8, textTransform: "uppercase" }}>{item.label}</div>
            <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 28, fontWeight: 700, color: item.color }}>{item.value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* Severity Distribution */}
        <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 20 }}>
          <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: "#4a5568", letterSpacing: 1, marginBottom: 16, textTransform: "uppercase" }}>Severity Distribution</div>
          {Object.entries(sevDist).map(([level, count]) => {
            const maxCount = Math.max(...Object.values(sevDist), 1);
            return (
              <div key={level} style={{ marginBottom: 14 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: sevColors[level] || "#8492a6", textTransform: "uppercase", fontWeight: 600 }}>{level}</span>
                  <span style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, fontWeight: 700, color: "#e2e8f0" }}>{count}</span>
                </div>
                <div style={{ height: 6, background: "#1e293b", borderRadius: 3, overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${(count / maxCount) * 100}%`, background: `linear-gradient(90deg, ${sevColors[level] || "#8492a6"}, ${sevColors[level] || "#8492a6"}88)`, borderRadius: 3, transition: "width 0.8s ease-out" }} />
                </div>
              </div>
            );
          })}
        </div>

        {/* Automated Actions */}
        <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 20 }}>
          <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: "#4a5568", letterSpacing: 1, marginBottom: 16, textTransform: "uppercase" }}>Automated Actions</div>
          {Object.entries(actions).map(([action, count]) => {
            const maxCount = Math.max(...Object.values(actions), 1);
            const actionColors = { block_ip: "#ef4444", isolate_host: "#f97316", kill_process: "#eab308", notify: "#3b82f6" };
            return (
              <div key={action} style={{ marginBottom: 14 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#8492a6", textTransform: "uppercase" }}>{action.replace("_", " ")}</span>
                  <span style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, fontWeight: 700, color: "#e2e8f0" }}>{count}</span>
                </div>
                <div style={{ height: 6, background: "#1e293b", borderRadius: 3, overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${(count / maxCount) * 100}%`, background: actionColors[action] || "#3b82f6", borderRadius: 3, transition: "width 0.8s ease-out" }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Top Sources */}
      {overview.top_sources && overview.top_sources.length > 0 && (
        <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 20, marginTop: 16 }}>
          <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: "#4a5568", letterSpacing: 1, marginBottom: 16, textTransform: "uppercase" }}>Top Alert Sources</div>
          <div style={{ display: "flex", gap: 12 }}>
            {overview.top_sources.map(s => (
              <div key={s.source} style={{ flex: 1, padding: 14, background: "#0a0e17", borderRadius: 6, textAlign: "center" }}>
                <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#3b82f6", marginBottom: 4 }}>{s.source}</div>
                <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 18, fontWeight: 700, color: "#e2e8f0" }}>{s.count}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
