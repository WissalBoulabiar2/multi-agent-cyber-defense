"""Plotly figures generated exclusively from experiment summary tables."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

# Fixed categorical slots (validated reference palette; first three slots are
# CVD-safe all-pairs). Colour follows the strategy, never its rank.
STRATEGY_COLORS = {"cooperative": "#2a78d6", "independent": "#eb6834", "centralized": "#1baf7a"}
FALLBACK = ["#2a78d6", "#eb6834", "#1baf7a"]
INK, INK_2, MUTED, GRID, AXIS = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"

METRIC_LABELS = {
    "detection.f1": "F1-score",
    "detection.precision": "Precision",
    "detection.recall": "Detection rate (recall)",
    "detection.fpr": "False positive rate",
    "detection.latency_sim_mean_s": "Detection latency (sim s)",
    "detection.latency_wall_mean_s": "Detection latency (wall s)",
    "detection.containment_rate": "Containment rate",
    "distributed.coordination_msgs_per_hour": "Coordination messages / sim-hour",
    "distributed.coordination_kb_per_hour": "Coordination KB / sim-hour",
    "distributed.delivery_latency_ms_mean": "Mean message delivery latency (ms)",
    "distributed.agent_processing_ms_mean": "Mean handler time per message (ms)",
    "distributed.cpu_s": "Process CPU time (s)",
    "distributed.wall_s": "Wall time per run (s)",
    "distributed.peak_rss_mb": "Peak RSS (MB)",
    "response.false_containments": "False containment actions",
}


def _layout(fig, title: str, ytitle: str, xtitle: str):
    fig.update_layout(
        title=dict(text=title, x=0.0, xanchor="left", font=dict(size=15, color=INK)),
        plot_bgcolor="#fcfcfb", paper_bgcolor="#fcfcfb", barmode="group", bargap=0.3, bargroupgap=0.06,
        yaxis_title=ytitle, xaxis_title=xtitle, legend_title_text="",
        legend=dict(orientation="h", y=1.02, yanchor="bottom", x=0.0, font=dict(color=INK_2)),
        margin=dict(l=60, r=20, t=80, b=50), font=dict(family="system-ui, Segoe UI, sans-serif", size=12, color=INK_2),
        hoverlabel=dict(bgcolor="#ffffff", font_color=INK),
    )
    fig.update_yaxes(gridcolor=GRID, gridwidth=1, zeroline=False, linecolor=AXIS, tickfont=dict(color=MUTED))
    fig.update_xaxes(linecolor=AXIS, tickfont=dict(color=MUTED), showgrid=False)
    fig.update_traces(marker_line_color="#fcfcfb", marker_line_width=2)
    return fig


def grouped_bar(summary: pd.DataFrame, metric: str, x: str, color: str | None, title: str):
    import plotly.graph_objects as go

    fig = go.Figure()
    sub = summary[summary["metric"] == metric]
    groups = list(dict.fromkeys(sub[color])) if color else [None]
    for i, g in enumerate(groups):
        part = sub if g is None else sub[sub[color] == g]
        c = STRATEGY_COLORS.get(str(g), FALLBACK[i % len(FALLBACK)])
        fig.add_bar(
            name=str(g) if g is not None else metric, x=[str(v) for v in part[x]], y=part["mean"], marker_color=c,
            error_y=dict(type="data", symmetric=False, array=(part["ci_hi"] - part["mean"]).clip(lower=0),
                         arrayminus=(part["mean"] - part["ci_lo"]).clip(lower=0), thickness=1.2, width=4),
            hovertemplate=f"{x}=%{{x}}<br>mean=%{{y:.4g}}<extra>{g}</extra>",
        )
    return _layout(fig, title, METRIC_LABELS.get(metric, metric), x)


def write_figures(summary: pd.DataFrame, out_dir: Path, x: str, color: str | None, metrics: list[str], suite: str) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for m in metrics:
        if m not in set(summary["metric"]):
            continue
        fig = grouped_bar(summary, m, x, color, f"{suite}: {METRIC_LABELS.get(m, m)} (mean, 95% bootstrap CI)")
        p = out_dir / f"{suite}__{m.replace('.', '_')}.html"
        fig.write_html(p, include_plotlyjs="cdn", full_html=True)
        paths.append(p)
        try:  # static export only if kaleido is installed
            fig.write_image(p.with_suffix(".png"), width=900, height=500, scale=2)
        except Exception:
            pass
    return paths
