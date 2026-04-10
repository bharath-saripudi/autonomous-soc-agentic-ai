import React from "react";

export default function MetricsCard({ label, value, color = "#3b82f6" }) {
  return (
    <div style={{
      background: "#111827", border: "1px solid #1e293b", borderRadius: 8,
      padding: "14px 16px", position: "relative", overflow: "hidden",
    }}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${color}, transparent)`, opacity: 0.5 }} />
      <div style={{ fontFamily: "'DM Sans'", fontSize: 10, color: "#8492a6", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>{label}</div>
      <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 22, fontWeight: 700, color: "#e2e8f0" }}>{value}</div>
    </div>
  );
}
