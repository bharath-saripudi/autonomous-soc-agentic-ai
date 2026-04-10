import React, { useState, useEffect } from "react";
import SeverityBadge from "../components/SeverityBadge";

const API_BASE = "http://localhost:8000";

export default function AlertFeed({ onSelect, wsMessages }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");

  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${API_BASE}/alerts?per_page=100`);
      if (res.ok) {
        const data = await res.json();
        setAlerts(data.alerts || []);
      }
    } catch (e) { console.error("Fetch failed:", e); }
    setLoading(false);
  };

  useEffect(() => { fetchAlerts(); const iv = setInterval(fetchAlerts, 8000); return () => clearInterval(iv); }, []);
  useEffect(() => { if (wsMessages.length > 0) fetchAlerts(); }, [wsMessages]);

  const getSeverity = (score) => {
    if (score >= 0.9) return "critical";
    if (score >= 0.7) return "high";
    if (score >= 0.4) return "medium";
    if (score >= 0.16) return "low";
    return "info";
  };

  const filtered = alerts.filter(a => {
    if (filter !== "all" && a.triage_score != null && getSeverity(a.triage_score) !== filter) return false;
    if (search && !a.source?.includes(search) && !a.id?.includes(search)) return false;
    return true;
  });

  return (
    <div>
      {/* Filters */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16, alignItems: "center" }}>
        <input placeholder="Search alerts..." value={search} onChange={e => setSearch(e.target.value)}
          style={{ flex: 1, padding: "8px 14px", background: "#111827", border: "1px solid #1e293b", borderRadius: 6, color: "#e2e8f0", fontFamily: "'JetBrains Mono'", fontSize: 12, outline: "none" }} />
        {["all", "critical", "high", "medium", "low"].map(s => (
          <button key={s} onClick={() => setFilter(s)}
            style={{ padding: "6px 12px", borderRadius: 4, border: `1px solid ${filter === s ? "#3b82f6" : "#1e293b"}`, background: filter === s ? "#3b82f615" : "transparent", color: filter === s ? "#3b82f6" : "#8492a6", fontFamily: "'JetBrains Mono'", fontSize: 10, cursor: "pointer", textTransform: "uppercase" }}>
            {s}
          </button>
        ))}
        <button onClick={fetchAlerts}
          style={{ padding: "6px 12px", borderRadius: 4, border: "1px solid #1e293b", background: "transparent", color: "#3b82f6", fontFamily: "'JetBrains Mono'", fontSize: 10, cursor: "pointer" }}>
          REFRESH ↻
        </button>
      </div>

      {/* Table */}
      <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #1e293b" }}>
              {["SOURCE", "STATUS", "SEVERITY", "SCORE", "CONFIDENCE", "FALSE POS", "CREATED"].map(h => (
                <th key={h} style={{ padding: "10px 14px", fontFamily: "'JetBrains Mono'", fontSize: 9, fontWeight: 600, color: "#4a5568", textAlign: "left", letterSpacing: 1 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} style={{ padding: 30, textAlign: "center", color: "#8492a6", fontFamily: "'JetBrains Mono'", fontSize: 12 }}>Loading...</td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: 30, textAlign: "center", color: "#8492a6", fontFamily: "'JetBrains Mono'", fontSize: 12 }}>No alerts found</td></tr>
            ) : filtered.map(a => {
              const sev = a.triage_score != null ? getSeverity(a.triage_score) : null;
              return (
                <tr key={a.id} onClick={() => onSelect(a.id)}
                  style={{ borderBottom: "1px solid #1e293b08", cursor: "pointer", transition: "background 0.15s" }}
                  onMouseEnter={e => e.currentTarget.style.background = "#1a2235"}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                  <td style={{ padding: "10px 14px", fontFamily: "'JetBrains Mono'", fontSize: 11, color: "#3b82f6" }}>{a.source}</td>
                  <td style={{ padding: "10px 14px", fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#8492a6" }}>{(a.status || "—").toUpperCase()}</td>
                  <td style={{ padding: "10px 14px" }}>{sev ? <SeverityBadge severity={sev} /> : <span style={{ color: "#4a5568" }}>—</span>}</td>
                  <td style={{ padding: "10px 14px", fontFamily: "'JetBrains Mono'", fontSize: 12, fontWeight: 600, color: sev ? ({ critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#6b7280" }[sev]) : "#4a5568" }}>{a.triage_score?.toFixed(2) ?? "—"}</td>
                  <td style={{ padding: "10px 14px", fontFamily: "'JetBrains Mono'", fontSize: 11, color: (a.confidence || 0) > 0.85 ? "#10b981" : "#8492a6" }}>{a.confidence?.toFixed(2) ?? "—"}</td>
                  <td style={{ padding: "10px 14px", fontFamily: "'JetBrains Mono'", fontSize: 10, color: a.is_false_positive ? "#22c55e" : "#4a5568" }}>{a.is_false_positive ? "YES" : "NO"}</td>
                  <td style={{ padding: "10px 14px", fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#4a5568" }}>{a.created_at ? new Date(a.created_at).toLocaleString() : "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
