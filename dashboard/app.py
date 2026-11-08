"""Streamlit dashboard for the Multi-Agent Cyber Defense prototype.

    streamlit run dashboard/app.py          (API_URL defaults to http://localhost:8000)

Everything shown comes from the FastAPI service (live simulation) or from
experiment artifacts under results/ (offline evaluation). Nothing is mocked.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import httpx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

API = os.environ.get("API_URL", "http://localhost:8000")
ROOT = Path(__file__).resolve().parents[1]

# Reference palette (fixed categorical slots; status colours are reserved)
C = {"blue": "#2a78d6", "orange": "#eb6834", "aqua": "#1baf7a", "ink": "#0b0b0b", "ink2": "#52514e",
     "muted": "#898781", "grid": "#e1e0d9", "surface": "#fcfcfb"}
STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}
SEVERITY_NAMES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
DOMAIN_LAYER = {"env": 0, "network": 1, "auth": 1, "config": 1, "central": 2, "intel": 2, "response": 3, "human": 4}

st.set_page_config(page_title="Multi-Agent Cyber Defense", layout="wide")


def get(path: str, **params):
    try:
        r = httpx.get(f"{API}{path}", params=params, timeout=5)
        return r.json() if r.status_code == 200 else None
    except httpx.HTTPError:
        return None


def post(path: str, json: dict | None = None):
    try:
        return httpx.post(f"{API}{path}", json=json or {}, timeout=10)
    except httpx.HTTPError as exc:
        st.error(f"API unreachable: {exc}")
        return None


def style(fig, title: str, height: int = 320):
    fig.update_layout(title=dict(text=title, x=0, font=dict(size=14, color=C["ink"])), height=height,
                      plot_bgcolor=C["surface"], paper_bgcolor=C["surface"],
                      font=dict(family="system-ui, Segoe UI, sans-serif", color=C["ink2"], size=12),
                      margin=dict(l=40, r=10, t=50, b=30), legend=dict(orientation="h", y=1.02, yanchor="bottom", x=0))
    fig.update_yaxes(gridcolor=C["grid"], zeroline=False)
    fig.update_xaxes(showgrid=False)
    return fig


# ------------------------------------------------------------------ sidebar
st.sidebar.title("Simulation control")
st.sidebar.caption("Isolated simulation — no real systems are touched.")
with st.sidebar.form("start"):
    strategy = st.selectbox("Coordination strategy", ["cooperative", "independent", "centralized"])
    scenarios = st.multiselect("Scenarios", ["credential_compromise", "lateral_movement", "configuration_tampering",
                                             "multi_stage"], default=["multi_stage"])
    seed = st.number_input("Seed", value=1, step=1)
    speedup = st.slider("Speed-up (sim s per wall s)", 10, 600, 60)
    n_sensors = st.selectbox("Sensor agents", [3, 2, 4, 8, 16], index=0)
    approval = st.radio("Critical-action approval", ["human", "auto"], horizontal=True)
    if st.form_submit_button("Start simulation"):
        r = post("/simulation/start", {"strategy": strategy, "scenarios": scenarios or ["multi_stage"], "seed": int(seed),
                                       "speedup": float(speedup), "n_sensors": int(n_sensors), "approval_mode": approval})
        if r is not None and r.status_code != 200:
            st.sidebar.error(r.text)
if st.sidebar.button("Stop simulation"):
    post("/simulation/stop")
auto = st.sidebar.toggle("Auto-refresh (2 s)", value=True)

# ------------------------------------------------------------------ header
st.title("Multi-Agent Cyber Defense — Distributed Detection & Response")
status = get("/simulation/status")
if status is None:
    st.warning(f"API not reachable at {API}. Start it with `uvicorn mcd.api.main:app`. Offline experiment results are still shown below.")
    status = {}

tab_live, tab_comm, tab_resp, tab_exp = st.tabs(["Live operations", "Agent interactions", "Response & audit", "Experiments"])

with tab_live:
    agents = get("/agents") or []
    metrics = (get("/metrics") or {}).get("live", {})
    incidents = get("/incidents") or []
    k = st.columns(6)
    active = sum(1 for a in agents if a["health"] in ("RUNNING", "STARTING"))
    k[0].metric("Active agents", f"{active}/{len(agents)}")
    k[1].metric("Sim time", f"{status.get('sim_time', 0) / 60:.0f} min")
    k[2].metric("Events observed", metrics.get("events_seen", 0))
    k[3].metric("Shared alerts", metrics.get("alerts_seen", 0))
    k[4].metric("Incidents", len(incidents))
    k[5].metric("Actionable incidents", sum(1 for i in incidents if i.get("actionable")))

    c1, c2 = st.columns([1.1, 1])
    with c1:
        st.subheader("Agent health")
        if agents:
            df = pd.DataFrame(agents)
            df["status"] = df["health"].map(lambda h: {"RUNNING": "● running", "DEGRADED": "▲ degraded", "DOWN": "✖ down"}.get(h, h))
            st.dataframe(df[["agent_id", "domain", "status", "processed", "failed", "queue_depth", "last_heartbeat_age_s"]],
                         hide_index=True, use_container_width=True)
    with c2:
        sev = metrics.get("severity_distribution", {})
        fig = go.Figure(go.Bar(x=[SEVERITY_NAMES[int(s)] for s in sev], y=list(sev.values()), marker_color=C["blue"],
                               marker_line_color=C["surface"], marker_line_width=2,
                               hovertemplate="%{x}: %{y} alerts<extra></extra>"))
        st.plotly_chart(style(fig, "Shared-alert severity distribution"), use_container_width=True)

    st.subheader("Cooperative decisions (global assessments)")
    if incidents:
        df = pd.DataFrame(incidents)
        df["targets"] = df["targets"].map(lambda ts: ", ".join(t["entity"]["id"] for t in ts))
        df["domains"] = df["domains"].map(lambda d: ", ".join(d))
        st.dataframe(df[["incident_id", "status", "actionable", "threat_class", "global_confidence", "severity",
                         "domains", "targets", "decision_source", "explanation"]], hide_index=True, use_container_width=True)
    else:
        st.caption("No assessment yet.")

    c3, c4 = st.columns(2)
    with c3:
        st.subheader("Detected anomalies / shared alerts")
        al = get("/alerts", limit=100) or []
        if al:
            st.dataframe(pd.DataFrame(al)[["sim_time", "agent_id", "alert_type", "entity", "status", "confidence",
                                           "anomaly_score", "rule_confidence"]].iloc[::-1], hide_index=True, use_container_width=True, height=300)
    with c4:
        st.subheader("Incoming security events (sample)")
        ev = get("/events/recent", limit=100) or []
        if ev:
            st.dataframe(pd.DataFrame(ev).iloc[::-1], hide_index=True, use_container_width=True, height=300)

with tab_comm:
    st.subheader("Inter-agent communication (messages since start)")
    comm = (get("/communications") or {}).get("edges", [])
    if comm:
        nodes = sorted({e["source"] for e in comm} | {e["target"] for e in comm})

        def layer(n: str) -> int:
            p = n.split("-")[0].split(":")[0]
            return {"net": 1, "auth": 1, "cfg": 1, "intel": 2, "central": 2, "response": 3, "operator": 4,
                    "human": 4, "env": 0}.get(p, 4)

        by_layer: dict[int, list[str]] = {}
        for n in nodes:
            by_layer.setdefault(layer(n), []).append(n)
        pos = {n: (lv, i - (len(ns) - 1) / 2) for lv, ns in by_layer.items() for i, n in enumerate(ns)}
        fig = go.Figure()
        mx = max(e["messages"] for e in comm)
        for e in comm:
            (x0, y0), (x1, y1) = pos[e["source"]], pos[e["target"]]
            fig.add_trace(go.Scatter(x=[x0, x1], y=[y0, y1], mode="lines", hoverinfo="text",
                                     text=f"{e['source']} → {e['target']}: {e['messages']} msgs on {e['topic']}",
                                     line=dict(width=1 + 6 * e["messages"] / mx, color="rgba(42,120,214,0.45)"), showlegend=False))
        fig.add_trace(go.Scatter(x=[pos[n][0] for n in nodes], y=[pos[n][1] for n in nodes], mode="markers+text",
                                 text=nodes, textposition="top center", marker=dict(size=16, color=C["blue"],
                                 line=dict(color=C["surface"], width=2)), hoverinfo="text", showlegend=False))
        fig.update_xaxes(tickvals=[0, 1, 2, 3, 4], ticktext=["environment", "sensors", "coordination", "response", "operator"])
        fig.update_yaxes(visible=False)
        st.plotly_chart(style(fig, "Agent interaction graph (edge width ∝ messages)", 460), use_container_width=True)
        st.dataframe(pd.DataFrame(comm).sort_values("messages", ascending=False), hide_index=True, use_container_width=True)

    st.subheader("Threat propagation (entities implicated by incidents)")
    inc = get("/incidents") or []
    if inc:
        fig = go.Figure()
        ent_nodes, edges = {}, []
        for i, a in enumerate(inc[:12]):
            iid = a["incident_id"][-6:]
            ent_nodes[iid] = ("incident", a["global_confidence"], a["actionable"])
            for t in a["targets"] + [{"entity": e} for e in a["entities"][:6]]:
                key = f"{t['entity']['kind']}:{t['entity']['id']}"
                ent_nodes.setdefault(key, (t["entity"]["kind"], 0, False))
                edges.append((iid, key))
        names = list(ent_nodes)
        import math
        pos = {n: (math.cos(2 * math.pi * i / len(names)), math.sin(2 * math.pi * i / len(names))) for i, n in enumerate(names)}
        for a, b in edges:
            fig.add_trace(go.Scatter(x=[pos[a][0], pos[b][0]], y=[pos[a][1], pos[b][1]], mode="lines",
                                     line=dict(color=C["grid"], width=1.5), hoverinfo="skip", showlegend=False))
        for kind, color in (("incident", C["orange"]), ("host", C["blue"]), ("user", C["aqua"])):
            ns = [n for n in names if ent_nodes[n][0] == kind]
            fig.add_trace(go.Scatter(x=[pos[n][0] for n in ns], y=[pos[n][1] for n in ns], mode="markers+text", name=kind,
                                     text=[n.split(":")[-1] for n in ns], textposition="top center",
                                     marker=dict(size=[18 if ent_nodes[n][2] else 12 for n in ns], color=color,
                                                 line=dict(color=C["surface"], width=2))))
        fig.update_xaxes(visible=False)
        fig.update_yaxes(visible=False)
        st.plotly_chart(style(fig, "Incidents (orange, large = actionable) and implicated hosts / users", 480), use_container_width=True)

with tab_resp:
    st.subheader("Pending human approvals (critical actions)")
    pend = get("/approvals", pending_only=True) or []
    if not pend:
        st.caption("No action awaiting approval.")
    for p in pend:
        cmd = p["command"]
        cols = st.columns([4, 1, 1])
        cols[0].markdown(f"**{cmd['action']}** on `{cmd['target']['id']}` — confidence {p['confidence']:.2f}  \n{p['rationale']}")
        if cols[1].button("Approve", key=f"a{p['action_id']}"):
            post(f"/approvals/{p['action_id']}", {"approved": True, "operator": "dashboard"})
        if cols[2].button("Reject", key=f"r{p['action_id']}"):
            post(f"/approvals/{p['action_id']}", {"approved": False, "operator": "dashboard"})
    st.subheader("Simulated defensive actions")
    acts = get("/actions") or []
    if acts:
        st.dataframe(pd.DataFrame(acts), hide_index=True, use_container_width=True)
    st.subheader("Incident history — audit log (hash-chained)")
    aud = get("/audit") or []
    if aud:
        st.dataframe(pd.DataFrame(aud)[["seq", "sim_time", "incident_id", "detected_threat", "responsible_agent",
                                        "threat_confidence", "selected_response", "target", "approval",
                                        "response_outcome", "hash"]].iloc[::-1], hide_index=True, use_container_width=True)
    final = (get("/metrics") or {}).get("final")
    if final:
        st.subheader("Detection performance of the finished run (vs ground truth)")
        d = final["detection"]
        k = st.columns(6)
        for col, (name, key) in zip(k, [("Precision", "precision"), ("Recall", "recall"), ("F1", "f1"), ("FPR", "fpr"),
                                         ("Latency (sim s)", "latency_sim_mean_s"), ("Containment", "containment_rate")]):
            v = d.get(key)
            col.metric(name, "n/a" if v is None or v != v else f"{v:.3f}")

with tab_exp:
    st.subheader("Offline experiments (results/)")
    suites = sorted((ROOT / "results").glob("e*/summary.csv"))
    if not suites:
        st.info("No experiment results yet. Run `python -m mcd.evaluation.experiments --all`.")
    for s in suites:
        with st.expander(s.parent.name, expanded=False):
            rep = s.parent / "report.md"
            if rep.exists():
                st.markdown(rep.read_text(encoding="utf-8"))
            for fig_path in sorted((s.parent / "figures").glob("*.html"))[:8]:
                st.components.v1.html(fig_path.read_text(encoding="utf-8"), height=520, scrolling=False)

if auto and status.get("running"):
    time.sleep(2)
    st.rerun()
