"""Reproducible experiment runner.

    python -m mcd.evaluation.experiments configs/experiments/e1_strategies.yaml
    python -m mcd.evaluation.experiments --all [--seeds 100 101 102] [--out results]

A suite YAML defines ``base`` (SystemConfig overrides), a ``grid`` of variables
(cartesian product), ``seeds`` and optional named ``presets`` for complex values.
Every run is executed for real; rows.csv holds one line per run, summary.csv the
aggregated means with 95% bootstrap CIs, tests.csv paired Wilcoxon tests, and
report.md a human-readable report citing run identifiers.
"""

from __future__ import annotations

import argparse
import copy
import itertools
import json
import logging
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from mcd.communication.conditions import DEFAULT_SCOPE
from mcd.evaluation.metrics import flatten
from mcd.evaluation.statistics import bootstrap_ci, holm, paired_wilcoxon
from mcd.evaluation.visualizations import write_figures
from mcd.runtime.system import SystemConfig, run_system

log = logging.getLogger("mcd.experiments")
ROOT = Path(__file__).resolve().parents[3]

KEY_METRICS = [
    "detection.f1", "detection.precision", "detection.recall", "detection.fpr",
    "detection.latency_sim_mean_s", "detection.latency_wall_mean_s", "detection.containment_rate",
    "distributed.coordination_msgs_per_hour", "distributed.coordination_kb_per_hour",
    "distributed.delivery_latency_ms_mean", "distributed.agent_processing_ms_mean",
    "distributed.cpu_s", "distributed.wall_s", "distributed.peak_rss_mb", "response.false_containments",
]
TEST_METRICS = ["detection.f1", "detection.precision", "detection.recall", "detection.fpr",
                "detection.latency_sim_mean_s", "distributed.coordination_msgs_per_hour"]


def _set(d: dict, dotted: str, value: Any) -> None:
    cur = d
    parts = dotted.split(".")
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def build_config(suite: dict, point: dict[str, Any], seed: int, out_dir: Path | None) -> SystemConfig:
    cfg = copy.deepcopy(suite.get("base", {}))
    presets = suite.get("presets", {})
    scen_presets = suite.get("scenario_presets", {})
    for key, value in point.items():
        if key == "scenario":
            cfg["scenarios"] = copy.deepcopy(scen_presets.get(value, [{"type": value}]))
        elif key in presets:
            for k, v in copy.deepcopy(presets[key][value]).items():
                _set(cfg, k, v)
        else:
            _set(cfg, key, value)
    if cfg.pop("scale_topology_with_sensors", False) and cfg.get("n_sensors"):
        _set(cfg, "topology.scale", max(0.5, cfg["n_sensors"] / 4))
    if suite.get("central_ingest_conditions") and cfg.get("strategy") == "centralized":
        # the centralized baseline depends on edge->centre raw-event transfer
        _set(cfg, "conditions.applies_to", list(DEFAULT_SCOPE) + ["sim.*"])
    cfg["seed"] = seed
    cfg["run_name"] = "__".join(f"{k}={v}" for k, v in point.items()) + f"__seed={seed}"
    if out_dir is not None and suite.get("save_runs", False):
        cfg["output_dir"] = str(out_dir / "runs" / cfg["run_name"])
    return SystemConfig.model_validate(cfg)


def _git_commit() -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return None


def run_suite(path: Path, out_root: Path, seeds: list[int] | None = None, limit: int | None = None) -> Path:
    suite = yaml.safe_load(Path(path).read_text())
    name = suite["name"]
    out = out_root / name
    out.mkdir(parents=True, exist_ok=True)
    seeds = seeds or suite.get("seeds", [100, 101, 102])
    grid: dict[str, list] = suite.get("grid", {})
    keys = list(grid)
    points = [dict(zip(keys, combo)) for combo in itertools.product(*grid.values())] if keys else [{}]
    skip = suite.get("skip", [])
    points = [p for p in points if not any(all(p.get(k) == v for k, v in s.items()) for s in skip)]
    manifest = {"suite": name, "suite_file": str(path), "seeds": seeds, "grid": grid, "started": time.time(),
                "python": sys.version, "platform": platform.platform(), "git_commit": _git_commit(), "runs": []}
    rows = []
    total = len(points) * len(seeds)
    n = 0
    with (out / "runs.jsonl").open("w", encoding="utf-8") as fh:
        for p in points:
            for seed in seeds:
                n += 1
                if limit is not None and n > limit:
                    break
                cfg = build_config(suite, p, seed, out)
                t0 = time.time()
                result = run_system(cfg)
                flat = flatten(result["metrics"])
                row = {**{k: str(v) for k, v in p.items()}, "seed": seed, "run_name": cfg.run_name,
                       "config_hash": result["config_hash"], "n_sensor_agents": result["n_sensor_agents"], **flat}
                rows.append(row)
                fh.write(json.dumps({"row": row, "per_attack": result["metrics"]["detection"]["per_attack"],
                                     "shards": result["shards"], "agent_details": result["agent_details"],
                                     "audit_ok": result["audit_ok"]}, default=str) + "\n")
                fh.flush()
                manifest["runs"].append(cfg.run_name)
                log.warning("[%s %d/%d] %s f1=%.3f fpr=%.4f (%.1fs)", name, n, total, cfg.run_name,
                            flat.get("detection.f1", float("nan")), flat.get("detection.fpr", float("nan")), time.time() - t0)
    df = pd.DataFrame(rows)
    df.to_csv(out / "rows.csv", index=False)
    manifest["finished"] = time.time()
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    summarize(out, suite, df)
    return out


def summarize(out: Path, suite: dict, df: pd.DataFrame) -> None:
    keys = [k for k in suite.get("grid", {})]
    metrics = [m for m in KEY_METRICS if m in df.columns]
    recs = []
    for vals, g in (df.groupby(keys, sort=False) if keys else [((), df)]):
        vals = vals if isinstance(vals, tuple) else (vals,)
        for m in metrics:
            mean, lo, hi = bootstrap_ci(g[m].tolist())
            recs.append({**dict(zip(keys, vals)), "metric": m, "mean": mean, "ci_lo": lo, "ci_hi": hi,
                         "n": int(g[m].notna().sum())})
    summary = pd.DataFrame(recs)
    summary.to_csv(out / "summary.csv", index=False)

    tests = []
    if "strategy" in keys:
        others = [k for k in keys if k != "strategy"]
        strategies = list(dict.fromkeys(df["strategy"]))
        pairs = [(a, b) for a, b in (("cooperative", "independent"), ("cooperative", "centralized"))
                 if a in strategies and b in strategies]
        for ovals, g in (df.groupby(others, sort=False) if others else [((), df)]):
            ovals = ovals if isinstance(ovals, tuple) else (ovals,)
            label = ", ".join(f"{k}={v}" for k, v in zip(others, ovals)) or "all"
            for a, b in pairs:
                ga = g[g["strategy"] == a].set_index("seed")
                gb = g[g["strategy"] == b].set_index("seed")
                common = ga.index.intersection(gb.index)
                for m in TEST_METRICS:
                    if m in g.columns:
                        t = paired_wilcoxon(f"{m} [{label}]", a, b, ga.loc[common, m], gb.loc[common, m])
                        tests.append(t)
        holm(tests)
    tdf = pd.DataFrame([t.__dict__ for t in tests])
    if not tdf.empty:
        tdf.to_csv(out / "tests.csv", index=False)

    x = suite.get("x") or next((k for k in keys if k != "strategy"), keys[0] if keys else None)
    color = "strategy" if "strategy" in keys and x != "strategy" else None
    figs = []
    if x is not None:
        sub = summary
        extra = [k for k in keys if k not in (x, color)]
        if extra:  # one figure set per value of extra variables -> aggregate over them for the overview
            sub = summary.groupby([k for k in (x, color) if k] + ["metric"], sort=False).agg(
                mean=("mean", "mean"), ci_lo=("ci_lo", "mean"), ci_hi=("ci_hi", "mean"), n=("n", "sum")).reset_index()
        figs = write_figures(sub, out / "figures", x, color, suite.get("figure_metrics", metrics), suite["name"])
    write_report(out, suite, df, summary, tdf, figs)


def _fmt(v: float) -> str:
    if v != v:
        return "n/a"
    return f"{v:.3f}" if abs(v) < 1000 else f"{v:.0f}"


def write_report(out: Path, suite: dict, df: pd.DataFrame, summary: pd.DataFrame, tdf: pd.DataFrame, figs) -> None:
    keys = list(suite.get("grid", {}))
    lines = [f"# {suite['name']}", "", suite.get("description", "").strip(), "",
             f"Runs: {len(df)} (seeds: {sorted(set(df['seed']))}). All values are computed from these runs; "
             "per-run rows are in `rows.csv`, raw per-attack outcomes in `runs.jsonl`.", ""]
    show = [m for m in suite.get("report_metrics", TEST_METRICS) if m in set(summary["metric"])]
    piv_rows = []
    for vals, g in (summary.groupby(keys, sort=False) if keys else [((), summary)]):
        vals = vals if isinstance(vals, tuple) else (vals,)
        row = {k: v for k, v in zip(keys, vals)}
        for m in show:
            r = g[g["metric"] == m]
            if not r.empty:
                r = r.iloc[0]
                row[m] = f"{_fmt(r['mean'])} [{_fmt(r['ci_lo'])}, {_fmt(r['ci_hi'])}]"
        piv_rows.append(row)
    if piv_rows:
        cols = keys + show
        lines.append("## Results (mean [95% bootstrap CI])")
        lines.append("")
        lines.append("| " + " | ".join(cols) + " |")
        lines.append("|" + "---|" * len(cols))
        for r in piv_rows:
            lines.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
        lines.append("")
    if not tdf.empty:
        lines += ["## Paired comparisons (Wilcoxon signed-rank, Holm-corrected)", "",
                  "| metric | A | B | n | mean A | mean B | median(A-B) | p | p (Holm) | r |", "|---|---|---|---|---|---|---|---|---|---|"]
        for _, t in tdf.iterrows():
            lines.append(f"| {t['metric']} | {t['a']} | {t['b']} | {t['n']} | {_fmt(t['mean_a'])} | {_fmt(t['mean_b'])} | "
                         f"{_fmt(t['median_diff'])} | {_fmt(t['p_value'])} | {_fmt(t['p_holm'])} | {_fmt(t['effect_r'])} |")
        lines.append("")
    if figs:
        lines += ["## Figures", ""] + [f"- [{p.name}](figures/{p.name})" for p in figs] + [""]
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("suites", nargs="*", help="suite YAML files")
    ap.add_argument("--all", action="store_true", help="run every suite in configs/experiments")
    ap.add_argument("--seeds", type=int, nargs="*", help="override seeds")
    ap.add_argument("--out", default=str(ROOT / "results"))
    ap.add_argument("--limit", type=int, help="max runs per suite (smoke test)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s")
    paths = [Path(p) for p in args.suites]
    if args.all:
        paths = sorted((ROOT / "configs" / "experiments").glob("e*.yaml"))
    for p in paths:
        out = run_suite(p, Path(args.out), args.seeds, args.limit)
        print(f"wrote {out}")


if __name__ == "__main__":
    main()
