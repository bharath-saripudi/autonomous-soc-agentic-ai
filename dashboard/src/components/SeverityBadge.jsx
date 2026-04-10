import React from "react";

const config = {
  critical: { color: "#ef4444", bg: "rgba(239,68,68,0.15)", label: "CRITICAL" },
  high:     { color: "#f97316", bg: "rgba(249,115,22,0.15)", label: "HIGH" },
  medium:   { color: "#eab308", bg: "rgba(234,179,8,0.15)", label: "MEDIUM" },
  low:      { color: "#22c55e", bg: "rgba(34,197,94,0.15)", label: "LOW" },
  info:     { color: "#6b7280", bg: "rgba(107,114,128,0.15)", label: "INFO" },
};

export default function SeverityBadge({ severity }) {
  const c = config[severity] || config.info;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5, padding: "3px 10px",
      borderRadius: 4, fontSize: 10, fontWeight: 600, fontFamily: "'JetBrains Mono'",
      letterSpacing: 0.8, color: c.color, background: c.bg, border: `1px solid ${c.color}33`,
    }}>
      <span style={{ fontSize: 6 }}>⬤</span> {c.label}
    </span>
  );
}
