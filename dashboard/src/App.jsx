import { useState, useEffect, useCallback } from "react";
import { AreaChart, Area, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

const API = "http://localhost:8000";
const C = {
  void: "#050a12", abyss: "#0a1122", panel: "#0d1726", panelHover: "#111f33",
  surface: "#142038", border: "#1a2d4a", ghost: "#1f344d",
  text: "#d4dff0", sub: "#6b82a8", dim: "#3a516e",
  cyan: "#00d4ff", cyanGlow: "rgba(0,212,255,0.12)",
  red: "#ff2b5e", redGlow: "rgba(255,43,94,0.15)",
  orange: "#ff8a2b", orangeGlow: "rgba(255,138,43,0.12)",
  yellow: "#ffd02b", yellowGlow: "rgba(255,208,43,0.10)",
  green: "#00e88f", greenGlow: "rgba(0,232,143,0.12)",
  purple: "#8855ff",
  white04: "rgba(255,255,255,0.04)",
};
const SEV = {
  critical: { c: C.red, g: C.redGlow, l: "CRIT" },
  high: { c: C.orange, g: C.orangeGlow, l: "HIGH" },
  medium: { c: C.yellow, g: C.yellowGlow, l: "MED" },
  low: { c: C.green, g: C.greenGlow, l: "LOW" },
  info: { c: C.dim, g: C.white04, l: "INFO" },
};
const toSev = (s) => !s ? "info" : s >= .9 ? "critical" : s >= .7 ? "high" : s >= .4 ? "medium" : s >= .16 ? "low" : "info";
const mono = "'IBM Plex Mono', 'Fira Code', monospace";
const sans = "'IBM Plex Sans', 'Segoe UI', sans-serif";

const Num = ({ v, d = 0, suf = "" }) => {
  const [cur, set] = useState(0);
  useEffect(() => { let f = 0; const steps = 24, inc = (v - cur) / steps; const id = setInterval(() => { f++; set(p => f >= steps ? v : p + inc); if (f >= steps) clearInterval(id); }, 20); return () => clearInterval(id); }, [v]);
  return <span>{cur.toFixed(d)}{suf}</span>;
};

const SevBadge = ({ s }) => { const cfg = SEV[s] || SEV.info; return <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px", borderRadius: 3, fontSize: 10, fontWeight: 700, fontFamily: mono, letterSpacing: 1, color: cfg.c, background: cfg.g, border: `1px solid ${cfg.c}30` }}>&#9670; {cfg.l}</span>; };

const StatBadge = ({ s }) => { const c = s === "responded" ? C.green : s === "escalated" ? C.red : s === "closed" ? C.dim : C.cyan; return <span style={{ padding: "2px 7px", borderRadius: 3, fontSize: 9, fontWeight: 600, fontFamily: mono, color: c, background: `${c}15`, border: `1px solid ${c}25` }}>{(s || "").toUpperCase()}</span>; };

const Panel = ({ children, style }) => <div style={{ background: `linear-gradient(135deg, ${C.panel}, ${C.abyss})`, border: `1px solid ${C.border}`, borderRadius: 6, ...style }}>{children}</div>;

const KPI = ({ label, value, d, suf, color, sub: st }) => (
  <Panel style={{ padding: "16px 18px", position: "relative", overflow: "hidden" }}>
    <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent 10%, ${color}, transparent 90%)`, opacity: .7 }} />
    <div style={{ fontFamily: sans, fontSize: 10, fontWeight: 500, color: C.sub, textTransform: "uppercase", letterSpacing: 1.5, marginBottom: 8 }}>{label}</div>
    <div style={{ fontFamily: mono, fontSize: 26, fontWeight: 700, color: C.text, lineHeight: 1 }}>{typeof value === "number" ? <Num v={value} d={d || 0} suf={suf || ""} /> : value}</div>
    {st && <div style={{ fontFamily: mono, fontSize: 10, color: C.sub, marginTop: 6 }}>{st}</div>}
  </Panel>
);

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({});
  const [pipe, setPipe] = useState({});
  const [learn, setLearn] = useState({});
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [tab, setTab] = useState("overview");
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [live, setLive] = useState(false);
  const [clock, setClock] = useState(new Date());
  const [timeData, setTimeData] = useState([]);

  const pull = useCallback(async () => {
    try {
      const [a, s, p, l] = await Promise.all([
        fetch(`${API}/alerts?per_page=100`).then(r => r.ok ? r.json() : null).catch(() => null),
        fetch(`${API}/stats/overview`).then(r => r.ok ? r.json() : null).catch(() => null),
        fetch(`${API}/stats/pipeline`).then(r => r.ok ? r.json() : null).catch(() => null),
        fetch(`${API}/stats/learning`).then(r => r.ok ? r.json() : null).catch(() => null),
      ]);
      if (a?.alerts) setAlerts(a.alerts);
      if (s) setStats(s);
      if (p) setPipe(p);
      if (l) setLearn(l);
      setLive(!!(a || s));
    } catch { setLive(false); }
  }, []);

  useEffect(() => { pull(); const iv = setInterval(pull, 6000); const ck = setInterval(() => setClock(new Date()), 1000); return () => { clearInterval(iv); clearInterval(ck); }; }, [pull]);

  useEffect(() => {
    const buckets = {};
    const now = Date.now();
    for (let i = 23; i >= 0; i--) { const h = new Date(now - i * 3600000).getHours(); const key = `${h.toString().padStart(2, "0")}:00`; buckets[key] = { time: key, total: 0, critical: 0 }; }
    alerts.forEach(a => { const h = new Date(a.created_at).getHours(); const key = `${h.toString().padStart(2, "0")}:00`; if (buckets[key]) { buckets[key].total++; if (toSev(a.triage_score) === "critical") buckets[key].critical++; } });
    setTimeData(Object.values(buckets));
  }, [alerts]);

  const openDetail = async (id) => { setSelected(id); try { const r = await fetch(`${API}/alerts/${id}`); if (r.ok) setDetail(await r.json()); } catch { } };

  const sevCounts = pipe.severity_counts || stats.severity_distribution || {};
  const actions = pipe.action_counts || {};
  const processed = pipe.alerts_processed || 1;
  const pieData = Object.entries(sevCounts).filter(([, v]) => v > 0).map(([k, v]) => ({ name: k, value: v, color: SEV[k]?.c || C.dim }));
  const filtered = alerts.filter(a => { const sev = toSev(a.triage_score); if (filter !== "all" && sev !== filter) return false; if (search && !JSON.stringify(a).toLowerCase().includes(search.toLowerCase())) return false; return true; });

  return (
    <div style={{ minHeight: "100vh", background: C.void, color: C.text, fontFamily: sans }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap');*{margin:0;padding:0;box-sizing:border-box}::-webkit-scrollbar{width:5px}::-webkit-scrollbar-thumb{background:${C.ghost};border-radius:3px}@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(1.5)}}@keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}.rh:hover{background:${C.panelHover}!important}.tb{background:none;border:none;padding:9px 18px;color:${C.sub};font-family:${mono};font-size:10px;font-weight:600;letter-spacing:1.2px;cursor:pointer;border-bottom:2px solid transparent;transition:all .2s;text-transform:uppercase}.tb:hover{color:${C.text}}.tb.on{color:${C.cyan};border-bottom-color:${C.cyan}}`}</style>

      {/* Header */}
      <header style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 20px", borderBottom: `1px solid ${C.border}`, background: `linear-gradient(180deg, ${C.surface}, ${C.void})` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{ position: "relative", width: 36, height: 36 }}>
            <div style={{ position: "absolute", inset: 0, borderRadius: 8, background: `linear-gradient(135deg, ${C.cyan}, ${C.purple})`, opacity: .9 }} />
            <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", fontFamily: mono, fontSize: 15, fontWeight: 800, color: "#fff" }}>&#9672;</div>
          </div>
          <div>
            <div style={{ fontFamily: mono, fontSize: 14, fontWeight: 700, letterSpacing: 2.5, color: C.text }}>AUTONOMOUS SOC</div>
            <div style={{ fontFamily: mono, fontSize: 8, letterSpacing: 2, color: C.sub, marginTop: 1 }}>MULTI-AGENT THREAT INTELLIGENCE PLATFORM</div>
          </div>
          <div style={{ width: 1, height: 30, background: C.border, margin: "0 6px" }} />
          <div style={{ display: "flex", gap: 2, alignItems: "center" }}>
            {["INGEST", "TRIAGE", "ENRICH", "HUNT", "RESPOND", "LEARN"].map((n, i) => (
              <div key={n} style={{ display: "flex", alignItems: "center" }}>
                <div style={{ padding: "3px 8px", borderRadius: 3, fontSize: 8, fontFamily: mono, fontWeight: 600, letterSpacing: .8, color: i === 1 ? C.cyan : C.dim, background: i === 1 ? C.cyanGlow : "transparent", border: `1px solid ${i === 1 ? C.cyan + "40" : C.border}` }}>{n}</div>
                {i < 5 && <div style={{ width: 8, height: 1, background: C.ghost }} />}
              </div>
            ))}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 4, background: live ? C.greenGlow : C.redGlow, border: `1px solid ${live ? C.green : C.red}30` }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: live ? C.green : C.red, animation: "pulse 2s infinite" }} />
            <span style={{ fontFamily: mono, fontSize: 9, fontWeight: 600, color: live ? C.green : C.red }}>{live ? "OPERATIONAL" : "OFFLINE"}</span>
          </div>
          <div style={{ fontFamily: mono, fontSize: 11, color: C.sub }}>{clock.toLocaleTimeString()}</div>
        </div>
      </header>

      {/* Tabs */}
      <nav style={{ display: "flex", padding: "0 20px", borderBottom: `1px solid ${C.border}` }}>
        {[["overview", "OVERVIEW"], ["alerts", "ALERT QUEUE"], ["pipeline", "PIPELINE"], ["intel", "THREAT INTEL"]].map(([id, label]) => (
          <button key={id} className={`tb ${tab === id ? "on" : ""}`} onClick={() => { setTab(id); setSelected(null); setDetail(null); }}>{label}</button>
        ))}
      </nav>

      <main style={{ padding: 20, height: "calc(100vh - 96px)", overflowY: "auto" }}>

        {/* OVERVIEW */}
        {tab === "overview" && (
          <div style={{ animation: "fadeUp .3s ease-out" }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 12, marginBottom: 20 }}>
              <KPI label="Ingested" value={pipe.alerts_ingested || stats.total_alerts || 0} color={C.cyan} sub={`${stats.alerts_today || 0} today`} />
              <KPI label="Processed" value={pipe.alerts_processed || 0} color={C.green} sub={`${((pipe.alerts_processed || 0) / (pipe.alerts_ingested || 1) * 100).toFixed(1)}% success`} />
              <KPI label="Critical" value={sevCounts.critical || 0} color={C.red} sub="Immediate action" />
              <KPI label="Auto-Closed" value={pipe.auto_closed || 0} color={C.green} sub={`${((pipe.auto_closed || 0) / processed * 100).toFixed(0)}% automated`} />
              <KPI label="Escalated" value={pipe.escalated || 0} color={C.orange} sub="Human review" />
              <KPI label="Avg Response" value={pipe.avg_processing_time_sec || 0} d={1} suf="s" color={C.purple} sub="End-to-end" />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "5fr 2fr", gap: 12, marginBottom: 20 }}>
              <Panel style={{ padding: "16px 18px" }}>
                <div style={{ fontFamily: mono, fontSize: 10, color: C.sub, letterSpacing: 1.5, marginBottom: 14 }}>ALERT VOLUME 24H</div>
                <ResponsiveContainer width="100%" height={180}>
                  <AreaChart data={timeData}>
                    <defs>
                      <linearGradient id="gc" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={C.cyan} stopOpacity={.35} /><stop offset="100%" stopColor={C.cyan} stopOpacity={0} /></linearGradient>
                      <linearGradient id="gr" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={C.red} stopOpacity={.4} /><stop offset="100%" stopColor={C.red} stopOpacity={0} /></linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={C.ghost} />
                    <XAxis dataKey="time" tick={{ fontSize: 9, fill: C.dim, fontFamily: mono }} axisLine={{ stroke: C.ghost }} tickLine={false} />
                    <YAxis tick={{ fontSize: 9, fill: C.dim, fontFamily: mono }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 4, fontFamily: mono, fontSize: 10, color: C.text }} />
                    <Area type="monotone" dataKey="total" stroke={C.cyan} fill="url(#gc)" strokeWidth={2} />
                    <Area type="monotone" dataKey="critical" stroke={C.red} fill="url(#gr)" strokeWidth={1.5} />
                  </AreaChart>
                </ResponsiveContainer>
              </Panel>
              <Panel style={{ padding: "16px 18px", display: "flex", flexDirection: "column" }}>
                <div style={{ fontFamily: mono, fontSize: 10, color: C.sub, letterSpacing: 1.5, marginBottom: 10 }}>SEVERITY</div>
                <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <ResponsiveContainer width="100%" height={130}>
                    <PieChart><Pie data={pieData} cx="50%" cy="50%" innerRadius={36} outerRadius={56} paddingAngle={3} dataKey="value" stroke={C.abyss} strokeWidth={2}>{pieData.map((e, i) => <Cell key={i} fill={e.color} />)}</Pie></PieChart>
                  </ResponsiveContainer>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8, justifyContent: "center", marginTop: 6 }}>
                  {pieData.map(d => <div key={d.name} style={{ display: "flex", alignItems: "center", gap: 4 }}><span style={{ width: 8, height: 3, borderRadius: 1, background: d.color }} /><span style={{ fontFamily: mono, fontSize: 9, color: C.sub }}>{d.name}</span><span style={{ fontFamily: mono, fontSize: 9, color: C.text, fontWeight: 600 }}>{d.value}</span></div>)}
                </div>
              </Panel>
            </div>
            <Panel style={{ overflow: "hidden" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", borderBottom: `1px solid ${C.border}` }}>
                <span style={{ fontFamily: mono, fontSize: 10, color: C.sub, letterSpacing: 1.5 }}>RECENT ALERTS ({alerts.length})</span>
                <button onClick={() => setTab("alerts")} style={{ background: "none", border: `1px solid ${C.border}`, color: C.cyan, padding: "4px 10px", borderRadius: 3, fontFamily: mono, fontSize: 9, cursor: "pointer" }}>VIEW ALL &#8594;</button>
              </div>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr>{["SOURCE", "STATUS", "SEVERITY", "SCORE", "CONF", "FP", "TIME"].map(h => <th key={h} style={{ padding: "8px 14px", fontFamily: mono, fontSize: 8, fontWeight: 600, color: C.dim, textAlign: "left", letterSpacing: 1.2, borderBottom: `1px solid ${C.ghost}` }}>{h}</th>)}</tr></thead>
                <tbody>
                  {alerts.slice(0, 10).map((a, i) => { const sev = toSev(a.triage_score); return (
                    <tr key={a.id} className="rh" onClick={() => { setTab("alerts"); openDetail(a.id); }} style={{ cursor: "pointer", animation: `fadeUp .25s ease-out ${i * .03}s both`, borderBottom: `1px solid ${C.white04}` }}>
                      <td style={{ padding: "9px 14px", fontFamily: mono, fontSize: 11, color: C.cyan }}>{a.source}</td>
                      <td style={{ padding: "9px 14px" }}><StatBadge s={a.status} /></td>
                      <td style={{ padding: "9px 14px" }}><SevBadge s={sev} /></td>
                      <td style={{ padding: "9px 14px", fontFamily: mono, fontSize: 12, fontWeight: 700, color: SEV[sev]?.c }}>{a.triage_score?.toFixed(2) ?? ""}</td>
                      <td style={{ padding: "9px 14px", fontFamily: mono, fontSize: 11, color: (a.confidence || 0) > .85 ? C.green : C.sub }}>{a.confidence?.toFixed(2) ?? ""}</td>
                      <td style={{ padding: "9px 14px", fontFamily: mono, fontSize: 10, color: a.is_false_positive ? C.green : C.dim }}>{a.is_false_positive ? "YES" : ""}</td>
                      <td style={{ padding: "9px 14px", fontFamily: mono, fontSize: 9, color: C.dim }}>{new Date(a.created_at).toLocaleTimeString()}</td>
                    </tr>
                  ); })}
                </tbody>
              </table>
            </Panel>
          </div>
        )}

        {/* ALERT QUEUE */}
        {tab === "alerts" && !selected && (
          <div style={{ animation: "fadeUp .3s ease-out" }}>
            <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
              <input placeholder="Search alerts..." value={search} onChange={e => setSearch(e.target.value)} style={{ flex: 1, padding: "9px 14px", background: C.panel, border: `1px solid ${C.border}`, borderRadius: 5, color: C.text, fontFamily: mono, fontSize: 11, outline: "none" }} onFocus={e => e.target.style.borderColor = C.cyan} onBlur={e => e.target.style.borderColor = C.border} />
              {["all", "critical", "high", "medium", "low"].map(s => <button key={s} onClick={() => setFilter(s)} style={{ padding: "7px 14px", borderRadius: 4, fontFamily: mono, fontSize: 9, fontWeight: 700, cursor: "pointer", letterSpacing: 1, textTransform: "uppercase", border: `1px solid ${filter === s ? (SEV[s]?.c || C.cyan) : C.border}`, background: filter === s ? (SEV[s]?.g || C.cyanGlow) : "transparent", color: filter === s ? (SEV[s]?.c || C.cyan) : C.sub }}>{s}</button>)}
              <button onClick={pull} style={{ padding: "7px 14px", borderRadius: 4, fontFamily: mono, fontSize: 9, cursor: "pointer", border: `1px solid ${C.border}`, background: "transparent", color: C.cyan }}>REFRESH &#8635;</button>
            </div>
            <Panel style={{ overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr>{["SOURCE", "STATUS", "SEV", "SCORE", "CONF", "ACTIONS", "FP", "CREATED"].map(h => <th key={h} style={{ padding: "10px 12px", fontFamily: mono, fontSize: 8, fontWeight: 600, color: C.dim, textAlign: "left", letterSpacing: 1, borderBottom: `1px solid ${C.ghost}`, position: "sticky", top: 0, background: C.panel, zIndex: 1 }}>{h}</th>)}</tr></thead>
                <tbody>
                  {filtered.length === 0 ? <tr><td colSpan={8} style={{ padding: 40, textAlign: "center", fontFamily: mono, fontSize: 11, color: C.sub }}>{live ? "No alerts match" : "API offline"}</td></tr> : filtered.map(a => { const sev = toSev(a.triage_score); return (
                    <tr key={a.id} className="rh" onClick={() => openDetail(a.id)} style={{ cursor: "pointer", borderBottom: `1px solid ${C.white04}` }}>
                      <td style={{ padding: "8px 12px", fontFamily: mono, fontSize: 11, color: C.cyan }}>{a.source}</td>
                      <td style={{ padding: "8px 12px" }}><StatBadge s={a.status} /></td>
                      <td style={{ padding: "8px 12px" }}><SevBadge s={sev} /></td>
                      <td style={{ padding: "8px 12px", fontFamily: mono, fontSize: 12, fontWeight: 700, color: SEV[sev]?.c }}>{a.triage_score?.toFixed(2) ?? ""}</td>
                      <td style={{ padding: "8px 12px", fontFamily: mono, fontSize: 11, color: (a.confidence || 0) > .85 ? C.green : C.sub }}>{a.confidence?.toFixed(2) ?? ""}</td>
                      <td style={{ padding: "8px 12px", fontFamily: mono, fontSize: 10, color: (a.actions_taken?.length || 0) > 0 ? C.orange : C.dim }}>{a.actions_taken?.length || 0}</td>
                      <td style={{ padding: "8px 12px", fontFamily: mono, fontSize: 10, color: a.is_false_positive ? C.green : C.dim }}>{a.is_false_positive ? "FP" : ""}</td>
                      <td style={{ padding: "8px 12px", fontFamily: mono, fontSize: 9, color: C.dim }}>{new Date(a.created_at).toLocaleString()}</td>
                    </tr>
                  ); })}
                </tbody>
              </table>
            </Panel>
          </div>
        )}

        {/* DETAIL VIEW */}
        {tab === "alerts" && selected && (
          <div style={{ animation: "fadeUp .2s ease-out" }}>
            <button onClick={() => { setSelected(null); setDetail(null); }} style={{ background: "none", border: `1px solid ${C.border}`, color: C.cyan, padding: "5px 12px", borderRadius: 4, fontFamily: mono, fontSize: 10, cursor: "pointer", marginBottom: 16 }}>&#8592; BACK</button>
            {!detail ? <div style={{ fontFamily: mono, color: C.sub, padding: 30 }}>Loading...</div> : (() => { const al = detail.alert; const sev = toSev(al.triage_score); return (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <div>
                  <Panel style={{ padding: 18, marginBottom: 14 }}>
                    <div style={{ fontFamily: mono, fontSize: 9, color: C.dim, letterSpacing: 1.2, marginBottom: 14 }}>ALERT OVERVIEW</div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                      <div style={{ padding: 12, background: C.void, borderRadius: 4 }}><div style={{ fontFamily: mono, fontSize: 8, color: C.dim, marginBottom: 6 }}>SEVERITY</div><SevBadge s={sev} /></div>
                      <div style={{ padding: 12, background: C.void, borderRadius: 4 }}><div style={{ fontFamily: mono, fontSize: 8, color: C.dim, marginBottom: 6 }}>SCORE</div><div style={{ fontFamily: mono, fontSize: 22, fontWeight: 700, color: SEV[sev]?.c }}>{(al.triage_score || 0).toFixed(2)}</div></div>
                      <div style={{ padding: 12, background: C.void, borderRadius: 4 }}><div style={{ fontFamily: mono, fontSize: 8, color: C.dim, marginBottom: 6 }}>CONFIDENCE</div><div style={{ fontFamily: mono, fontSize: 22, fontWeight: 700, color: (al.confidence || 0) > .85 ? C.green : C.yellow }}>{(al.confidence || 0).toFixed(2)}</div></div>
                      <div style={{ padding: 12, background: C.void, borderRadius: 4 }}><div style={{ fontFamily: mono, fontSize: 8, color: C.dim, marginBottom: 6 }}>STATUS</div><StatBadge s={al.status} /></div>
                    </div>
                  </Panel>
                  {al.triage_reasoning && <Panel style={{ padding: 18, marginBottom: 14 }}><div style={{ fontFamily: mono, fontSize: 9, color: C.dim, letterSpacing: 1.2, marginBottom: 10 }}>AI TRIAGE REASONING</div><div style={{ fontFamily: mono, fontSize: 11, color: C.text, lineHeight: 1.7, whiteSpace: "pre-wrap" }}>{al.triage_reasoning}</div></Panel>}
                  <Panel style={{ padding: 18 }}><div style={{ fontFamily: mono, fontSize: 9, color: C.dim, letterSpacing: 1.2, marginBottom: 10 }}>RAW DATA</div><pre style={{ fontFamily: mono, fontSize: 10, color: C.sub, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 250, overflowY: "auto" }}>{JSON.stringify(detail.raw_data, null, 2)}</pre></Panel>
                </div>
                <div>
                  <Panel style={{ padding: 18, marginBottom: 14 }}>
                    <div style={{ fontFamily: mono, fontSize: 9, color: C.dim, letterSpacing: 1.2, marginBottom: 12 }}>AGENT PIPELINE TRACE</div>
                    {(detail.audit_trail || []).map((e, i, arr) => (
                      <div key={i} style={{ display: "flex", gap: 10, position: "relative", paddingBottom: i < arr.length - 1 ? 14 : 0 }}>
                        {i < arr.length - 1 && <div style={{ position: "absolute", left: 9, top: 18, bottom: 0, width: 1, background: C.ghost }} />}
                        <div style={{ width: 18, minWidth: 18, height: 18, borderRadius: "50%", background: C.void, border: `2px solid ${C.cyan}`, display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1 }}><span style={{ width: 4, height: 4, borderRadius: "50%", background: C.cyan }} /></div>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: "flex", justifyContent: "space-between" }}><span style={{ fontFamily: mono, fontSize: 9, fontWeight: 700, color: C.cyan, textTransform: "uppercase" }}>{e.agent}</span><span style={{ fontFamily: mono, fontSize: 8, color: C.dim }}>{e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : ""}</span></div>
                          <div style={{ fontFamily: mono, fontSize: 10, color: C.text, marginTop: 2 }}>{e.action?.replace(/_/g, " ")}</div>
                          {e.details && <div style={{ fontFamily: mono, fontSize: 8, color: C.sub, marginTop: 3, padding: "3px 6px", background: C.void, borderRadius: 3 }}>{typeof e.details === "object" ? Object.entries(e.details).map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join(" | ") : String(e.details)}</div>}
                        </div>
                      </div>
                    ))}
                  </Panel>
                  {al.actions_taken && al.actions_taken.length > 0 && <Panel style={{ padding: 18 }}><div style={{ fontFamily: mono, fontSize: 9, color: C.dim, letterSpacing: 1.2, marginBottom: 10 }}>RESPONSE ACTIONS</div>{al.actions_taken.map((act, i) => <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 0", borderBottom: i < al.actions_taken.length - 1 ? `1px solid ${C.ghost}` : "none" }}><span style={{ fontSize: 9, color: act.status === "executed" ? C.green : C.red }}>{act.status === "executed" ? "\u2713" : "\u2717"}</span><span style={{ fontFamily: mono, fontSize: 10, fontWeight: 600, color: C.text }}>{act.action?.replace(/_/g, " ").toUpperCase()}</span><span style={{ fontFamily: mono, fontSize: 9, color: C.sub, marginLeft: "auto" }}>{act.target}</span></div>)}</Panel>}
                </div>
              </div>
            ); })()}
          </div>
        )}

        {/* PIPELINE */}
        {tab === "pipeline" && (
          <div style={{ animation: "fadeUp .3s ease-out" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>
              <Panel style={{ padding: 20 }}>
                <div style={{ fontFamily: mono, fontSize: 10, color: C.sub, letterSpacing: 1.5, marginBottom: 18 }}>PERFORMANCE</div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                  {[{ l: "Success", v: `${((pipe.alerts_processed || 0) / (pipe.alerts_ingested || 1) * 100).toFixed(1)}%`, c: C.green }, { l: "Failure", v: `${((pipe.alerts_failed || 0) / (pipe.alerts_ingested || 1) * 100).toFixed(2)}%`, c: C.red }, { l: "Automation", v: `${((pipe.auto_closed || 0) / processed * 100).toFixed(0)}%`, c: C.cyan }, { l: "FP Rate", v: `${((pipe.false_positives || 0) / processed * 100).toFixed(0)}%`, c: C.yellow }].map(m => <div key={m.l} style={{ padding: 14, background: C.void, borderRadius: 5, border: `1px solid ${C.ghost}` }}><div style={{ fontFamily: mono, fontSize: 8, color: C.dim, letterSpacing: .8, marginBottom: 6, textTransform: "uppercase" }}>{m.l}</div><div style={{ fontFamily: mono, fontSize: 22, fontWeight: 700, color: m.c }}>{m.v}</div></div>)}
                </div>
              </Panel>
              <Panel style={{ padding: 20 }}>
                <div style={{ fontFamily: mono, fontSize: 10, color: C.sub, letterSpacing: 1.5, marginBottom: 18 }}>ACTIONS</div>
                {Object.entries(actions).map(([a, c]) => { const max = Math.max(...Object.values(actions), 1); const ac = { block_ip: C.red, isolate_host: C.orange, kill_process: C.yellow, notify: C.cyan }; return <div key={a} style={{ marginBottom: 14 }}><div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}><span style={{ fontFamily: mono, fontSize: 9, color: C.sub, textTransform: "uppercase" }}>{a.replace(/_/g, " ")}</span><span style={{ fontFamily: mono, fontSize: 10, fontWeight: 700, color: C.text }}>{c}</span></div><div style={{ height: 4, background: C.ghost, borderRadius: 2, overflow: "hidden" }}><div style={{ height: "100%", width: `${(c / max) * 100}%`, background: ac[a] || C.cyan, borderRadius: 2, transition: "width .8s" }} /></div></div>; })}
              </Panel>
            </div>
            <Panel style={{ padding: 24 }}>
              <div style={{ fontFamily: mono, fontSize: 10, color: C.sub, letterSpacing: 1.5, marginBottom: 20 }}>WORKFLOW GRAPH</div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
                {[{ l: "INGEST", d: "Normalize", c: C.cyan, n: pipe.alerts_ingested }, { l: "TRIAGE", d: "Claude AI", c: C.purple, n: pipe.alerts_processed }, { l: "ENRICH", d: "IOC Lookup", c: C.orange, n: pipe.alerts_processed }, { l: "HUNT", d: "Vector RAG", c: C.yellow, n: pipe.alerts_processed }, { l: "RESPOND", d: "Auto-Actions", c: C.green, n: (pipe.alerts_processed || 0) - (pipe.auto_closed || 0) }, { l: "LEARN", d: "RLHF", c: C.green, n: pipe.alerts_processed }].map((nd, i, arr) => <div key={nd.l} style={{ display: "flex", alignItems: "center" }}><div style={{ width: 110, padding: "14px 8px", borderRadius: 6, border: `1px solid ${nd.c}35`, background: `${nd.c}06`, textAlign: "center" }}><div style={{ fontFamily: mono, fontSize: 9, fontWeight: 800, color: nd.c, letterSpacing: 1.5, marginBottom: 3 }}>{nd.l}</div><div style={{ fontSize: 9, color: C.sub, marginBottom: 6 }}>{nd.d}</div><div style={{ fontFamily: mono, fontSize: 18, fontWeight: 700, color: C.text }}>{nd.n || 0}</div></div>{i < arr.length - 1 && <div style={{ width: 14, height: 1, background: `linear-gradient(90deg, ${nd.c}50, ${arr[i + 1].c}50)` }} />}</div>)}
              </div>
            </Panel>
          </div>
        )}

        {/* THREAT INTEL */}
        {tab === "intel" && (
          <div style={{ animation: "fadeUp .3s ease-out" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 20 }}>
              <KPI label="Alerts Analyzed" value={pipe.alerts_processed || 0} color={C.cyan} />
              <KPI label="False Positives" value={pipe.false_positives || 0} color={C.yellow} />
              <KPI label="Learning Rules" value={learn.learned_rules_count || 0} color={C.green} />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <Panel style={{ padding: 20 }}>
                <div style={{ fontFamily: mono, fontSize: 10, color: C.sub, letterSpacing: 1.5, marginBottom: 14 }}>HIGH SEVERITY ALERTS</div>
                {alerts.filter(a => (a.triage_score || 0) >= .7).slice(0, 8).map((a, i) => { const sev = toSev(a.triage_score); return <div key={a.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: `1px solid ${C.ghost}` }}><div style={{ display: "flex", alignItems: "center", gap: 8 }}><span style={{ fontFamily: mono, fontSize: 10, color: C.dim }}>{i + 1}.</span><SevBadge s={sev} /><span style={{ fontFamily: mono, fontSize: 11, color: C.text }}>{a.source}</span></div><div style={{ display: "flex", alignItems: "center", gap: 8 }}><span style={{ fontFamily: mono, fontSize: 10, color: SEV[sev]?.c }}>{a.triage_score?.toFixed(2)}</span><StatBadge s={a.status} /></div></div>; })}
              </Panel>
              <Panel style={{ padding: 20 }}>
                <div style={{ fontFamily: mono, fontSize: 10, color: C.sub, letterSpacing: 1.5, marginBottom: 14 }}>ALERT SOURCES</div>
                {(stats.top_sources || []).map(s => <div key={s.source} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: `1px solid ${C.ghost}` }}><span style={{ fontFamily: mono, fontSize: 11, color: C.cyan }}>{s.source}</span><span style={{ fontFamily: mono, fontSize: 11, fontWeight: 700, color: C.text }}>{s.count}</span></div>)}
              </Panel>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}