import React, { useState, useEffect } from "react";

const API_BASE = "http://localhost:8000";

export default function FeedbackForm() {
  const [pending, setPending] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [label, setLabel] = useState("agree");
  const [severity, setSeverity] = useState("");
  const [notes, setNotes] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [learningStats, setLearningStats] = useState({});

  useEffect(() => {
    fetch(`${API_BASE}/feedback/pending`).then(r => r.ok ? r.json() : null).then(d => { if (d) setPending(d.alerts || []); }).catch(() => {});
    fetch(`${API_BASE}/stats/learning`).then(r => r.ok ? r.json() : null).then(d => { if (d) setLearningStats(d); }).catch(() => {});
  }, [submitted]);

  const handleSubmit = async () => {
    if (!selectedId) return;
    try {
      const res = await fetch(`${API_BASE}/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_id: selectedId, label, correct_severity: severity || null, notes: notes || null }),
      });
      if (res.ok) { setSubmitted(true); setSelectedId(""); setNotes(""); setTimeout(() => setSubmitted(false), 3000); }
    } catch (e) { console.error(e); }
  };

  const labelOptions = ["agree", "disagree", "false_positive", "true_positive", "needs_review"];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
      {/* Feedback Form */}
      <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 24 }}>
        <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: "#4a5568", letterSpacing: 1, marginBottom: 20, textTransform: "uppercase" }}>Submit Analyst Feedback</div>

        {submitted && <div style={{ padding: 12, background: "#10b98115", border: "1px solid #10b98133", borderRadius: 6, color: "#10b981", fontFamily: "'JetBrains Mono'", fontSize: 12, marginBottom: 16 }}>✓ Feedback submitted — learning agent will process it</div>}

        <div style={{ marginBottom: 16 }}>
          <label style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#8492a6", display: "block", marginBottom: 6 }}>ALERT ID</label>
          <select value={selectedId} onChange={e => setSelectedId(e.target.value)} style={{ width: "100%", padding: "8px 12px", background: "#0a0e17", border: "1px solid #1e293b", borderRadius: 6, color: "#e2e8f0", fontFamily: "'JetBrains Mono'", fontSize: 11 }}>
            <option value="">Select an alert...</option>
            {pending.map(a => (
              <option key={a.id} value={a.id}>{a.id.slice(0,8)}... — {a.source} — Score: {a.triage_score?.toFixed(2) || "N/A"}</option>
            ))}
          </select>
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#8492a6", display: "block", marginBottom: 6 }}>LABEL</label>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {labelOptions.map(l => (
              <button key={l} onClick={() => setLabel(l)} style={{
                padding: "6px 14px", borderRadius: 4, fontFamily: "'JetBrains Mono'", fontSize: 10, cursor: "pointer",
                border: `1px solid ${label === l ? "#3b82f6" : "#1e293b"}`,
                background: label === l ? "#3b82f615" : "transparent",
                color: label === l ? "#3b82f6" : "#8492a6",
              }}>{l.replace("_", " ").toUpperCase()}</button>
            ))}
          </div>
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#8492a6", display: "block", marginBottom: 6 }}>CORRECT SEVERITY (optional)</label>
          <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ width: "100%", padding: "8px 12px", background: "#0a0e17", border: "1px solid #1e293b", borderRadius: 6, color: "#e2e8f0", fontFamily: "'JetBrains Mono'", fontSize: 11 }}>
            <option value="">Same as AI assessment</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Informational</option>
          </select>
        </div>

        <div style={{ marginBottom: 20 }}>
          <label style={{ fontFamily: "'JetBrains Mono'", fontSize: 10, color: "#8492a6", display: "block", marginBottom: 6 }}>NOTES</label>
          <textarea value={notes} onChange={e => setNotes(e.target.value)} placeholder="Additional context for the AI to learn from..."
            style={{ width: "100%", height: 80, padding: "8px 12px", background: "#0a0e17", border: "1px solid #1e293b", borderRadius: 6, color: "#e2e8f0", fontFamily: "'JetBrains Mono'", fontSize: 11, resize: "vertical" }} />
        </div>

        <button onClick={handleSubmit} disabled={!selectedId}
          style={{ width: "100%", padding: "10px 0", borderRadius: 6, border: "none", background: selectedId ? "linear-gradient(135deg, #3b82f6, #8b5cf6)" : "#1e293b", color: selectedId ? "#fff" : "#4a5568", fontFamily: "'JetBrains Mono'", fontSize: 12, fontWeight: 600, cursor: selectedId ? "pointer" : "default" }}>
          SUBMIT FEEDBACK
        </button>
      </div>

      {/* Learning Stats */}
      <div>
        <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 24, marginBottom: 16 }}>
          <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: "#4a5568", letterSpacing: 1, marginBottom: 16, textTransform: "uppercase" }}>Learning Agent Status</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div style={{ padding: 14, background: "#0a0e17", borderRadius: 6 }}>
              <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 9, color: "#8492a6", marginBottom: 4 }}>PENDING FEEDBACK</div>
              <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 20, fontWeight: 700, color: "#3b82f6" }}>{learningStats.pending_feedback || 0}</div>
            </div>
            <div style={{ padding: 14, background: "#0a0e17", borderRadius: 6 }}>
              <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 9, color: "#8492a6", marginBottom: 4 }}>BATCH SIZE</div>
              <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 20, fontWeight: 700, color: "#8492a6" }}>{learningStats.batch_size || 5}</div>
            </div>
            <div style={{ padding: 14, background: "#0a0e17", borderRadius: 6, gridColumn: "1 / -1" }}>
              <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 9, color: "#8492a6", marginBottom: 4 }}>LEARNED RULES</div>
              <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 20, fontWeight: 700, color: "#10b981" }}>{learningStats.learned_rules_count || 0}</div>
            </div>
          </div>
        </div>

        {(learningStats.learned_rules || []).length > 0 && (
          <div style={{ background: "#111827", border: "1px solid #1e293b", borderRadius: 8, padding: 24 }}>
            <div style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: "#4a5568", letterSpacing: 1, marginBottom: 12, textTransform: "uppercase" }}>Active Learned Rules</div>
            {learningStats.learned_rules.map((rule, i) => (
              <div key={i} style={{ padding: "8px 12px", background: "#0a0e17", borderRadius: 4, marginBottom: 8, fontFamily: "'JetBrains Mono'", fontSize: 11, color: "#e2e8f0", borderLeft: "3px solid #10b981" }}>{rule}</div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
