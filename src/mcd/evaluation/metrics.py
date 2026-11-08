"""Metrics computed from logged run artifacts against the ground-truth store.

Unit of decision: an *actionable decision* (independent: a local alert above
tau_act sent to the response agent; cooperative/centralized: an assessment with
status CORROBORATED/CONFIRMED). Each decision implicates target entities at a
sim time; we evaluate unique (entity, 60 s window) pairs so that message
duplication does not inflate scores.

* TP pair: entity belongs to an attack and the decision time lies in
  [t_start - window, t_end + grace].
* precision = |TP pairs| / |flagged pairs|
* detection rate (recall) = attacks with >= 1 TP pair / attacks that produced events
* FPR = |FP pairs| / |benign entity-windows| (entity-windows with observed activity
  that are not part of an attack window)
* detection latency = first TP decision sim time - attack t_start (and wall-clock)
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any

import numpy as np

from mcd.communication.topics import topic_class
from mcd.simulation.ground_truth import GroundTruth

COORD_CLASSES = ("alerts", "alerts.direct", "directed", "assessments")


def _f1(p: float, r: float) -> float:
    if not (p == p) or p + r == 0:  # nan precision (no decisions)
        return 0.0
    return 2 * p * r / (p + r)


def detection_metrics(gt: GroundTruth, decisions: list[dict], grace: float = 600.0,
                      step_wall: dict[float, float] | None = None) -> dict[str, Any]:
    w = gt.window
    attacks = [a for a in gt.attacks.values() if a.t_start is not None]
    spans = [(a, set(a.entities), a.t_start - w, a.t_end + grace) for a in attacks]
    attack_pairs = set()
    for a, ents, lo, hi in spans:
        for b in range(int(lo // w), int(hi // w) + 1):
            for e in ents:
                attack_pairs.add((e, b))
    benign_windows = sum(1 for p in gt.activity if p not in attack_pairs)

    flagged, tp, fp = set(), set(), set()
    first_hit: dict[str, dict] = {}
    tp_decisions = 0
    for d in decisions:
        t = d["sim_time"]
        b = int(t // w)
        hit_any = False
        for e in d["targets"]:
            pair = (e, b)
            flagged.add(pair)
            matched = [a for a, ents, lo, hi in spans if e in ents and lo <= t <= hi]
            if matched:
                tp.add(pair)
                hit_any = True
                for a in matched:
                    if a.attack_id not in first_hit or t < first_hit[a.attack_id]["sim_time"]:
                        first_hit[a.attack_id] = d
            else:
                fp.add(pair)
        tp_decisions += hit_any
    tp_only = tp
    fp_only = fp - tp
    precision = len(tp_only) / len(flagged) if flagged else float("nan")
    recall = len(first_hit) / len(attacks) if attacks else float("nan")
    lat_sim, lat_wall = [], []
    per_attack = {}
    for a in attacks:
        d = first_hit.get(a.attack_id)
        rec = {"scenario": a.scenario, "detected": d is not None, "t_start": a.t_start, "t_end": a.t_end,
               "halted_at": a.halted_at, "halt_reason": a.halt_reason, "n_events": a.n_events}
        if d is not None:
            ls = d["sim_time"] - a.t_start
            lat_sim.append(ls)
            rec["latency_sim_s"] = ls
            if step_wall:
                key = math.floor(a.t_start / w) * w
                if key in step_wall:
                    lw = d["wall_time"] - step_wall[key]
                    lat_wall.append(lw)
                    rec["latency_wall_s"] = lw
        per_attack[a.attack_id] = rec
    contained = [a for a in attacks if a.halted_at is not None and a.halted_at < a.scheduled_end]
    return {
        "n_attacks": len(attacks),
        "n_decisions": len(decisions),
        "tp_decisions": tp_decisions,
        "decision_precision": tp_decisions / len(decisions) if decisions else float("nan"),
        "flagged_pairs": len(flagged),
        "tp_pairs": len(tp_only),
        "fp_pairs": len(fp_only),
        "benign_entity_windows": benign_windows,
        "precision": precision,
        "recall": recall,
        "detection_rate": recall,
        "f1": _f1(precision, recall),
        "fpr": len(fp_only) / benign_windows if benign_windows else float("nan"),
        "latency_sim_mean_s": float(np.mean(lat_sim)) if lat_sim else float("nan"),
        "latency_wall_mean_s": float(np.mean(lat_wall)) if lat_wall else float("nan"),
        "containment_rate": len(contained) / len(attacks) if attacks else float("nan"),
        "containment_latency_sim_mean_s": float(np.mean([a.halted_at - a.t_start for a in contained])) if contained else float("nan"),
        "per_attack": per_attack,
    }


def response_metrics(result: dict, gt: GroundTruth) -> dict[str, Any]:
    attack_entities = {e for a in gt.attacks.values() for e in a.entities}
    halted = {e for a in gt.attacks.values() if a.halted_at is not None for e in a.entities}
    acts = [a for a in result["actions"] if a["action"] in ("ISOLATE_HOST", "SUSPEND_ACCOUNT", "REVERT_CONFIG")]
    executed = [a for a in acts if a["executed_at"] is not None]
    on_attack = [a for a in executed if a["target"] in attack_entities]
    agree = [a for a in executed if a["outcome"] in ("MITIGATED", "PARTIAL", "INEFFECTIVE")]
    agreement = [((a["outcome"] == "MITIGATED") == (a["target"] in halted)) for a in agree]
    return {
        "containment_actions": len(acts),
        "executed_actions": len(executed),
        "actions_on_attack_entities": len(on_attack),
        "false_containments": len(executed) - len(on_attack),
        "approvals_requested": sum(1 for a in result["actions"] if a["approval"] != "not_required"),
        "timed_out": sum(1 for a in result["actions"] if a["outcome"] == "TIMED_OUT"),
        "self_assessment_agreement": float(np.mean(agreement)) if agreement else float("nan"),
        "benign_events_blocked": result["env"]["blocked_benign"],
    }


def distributed_metrics(result: dict) -> dict[str, Any]:
    cfg = result["config"]
    hours = cfg["duration"] / 3600.0
    by_class_msgs: dict[str, int] = defaultdict(int)
    by_class_bytes: dict[str, int] = defaultdict(int)
    for topic, n in result["broker"]["published_msgs"].items():
        cls = "alerts.direct" if topic == "alerts.direct" else topic_class(topic)
        by_class_msgs[cls] += n
        by_class_bytes[cls] += result["broker"]["published_bytes"].get(topic, 0)
    coord_msgs = sum(by_class_msgs.get(c, 0) for c in COORD_CLASSES)
    coord_bytes = sum(by_class_bytes.get(c, 0) for c in COORD_CLASSES)
    lat_p50, lat_p95, lat_mean, proc_ms, proc_total = [], [], [], [], 0.0
    for aid, m in result["agent_metrics"].items():
        if m["processed"]:
            lat_p50.append(m["delivery_ms_p50"])
            lat_p95.append(m["delivery_ms_p95"])
            lat_mean.append(m["delivery_ms_mean"])
            proc_ms.append(m["handler_ms_mean"])
            proc_total += m["handler_s_total"]
    return {
        "messages_by_class": dict(by_class_msgs),
        "bytes_by_class": dict(by_class_bytes),
        "coordination_msgs": coord_msgs,
        "coordination_bytes": coord_bytes,
        "coordination_msgs_per_hour": coord_msgs / hours if hours else float("nan"),
        "coordination_kb_per_hour": coord_bytes / 1024 / hours if hours else float("nan"),
        "ingest_msgs": by_class_msgs.get("ingest", 0),
        "ingest_kb": by_class_bytes.get("ingest", 0) / 1024,
        "delivery_latency_ms_mean": float(np.mean(lat_mean)) if lat_mean else float("nan"),
        "delivery_latency_ms_p50_max": float(np.max(lat_p50)) if lat_p50 else float("nan"),
        "delivery_latency_ms_p95_max": float(np.max(lat_p95)) if lat_p95 else float("nan"),
        "agent_processing_ms_mean": float(np.mean(proc_ms)) if proc_ms else float("nan"),
        "agent_processing_s_total": proc_total,
        "wall_s": result["resources"]["wall_s"],
        "cpu_s": result["resources"]["cpu_s"],
        "peak_rss_mb": result["resources"]["peak_rss_mb"],
        "dropped_by_conditions": sum(result["conditions"]["dropped"].values()),
    }


def evaluate_run(result: dict, gt: GroundTruth, step_wall: dict[float, float] | None = None) -> dict[str, Any]:
    return {
        "detection": detection_metrics(gt, result["decisions"], step_wall=step_wall),
        "response": response_metrics(result, gt),
        "distributed": distributed_metrics(result),
    }


def flatten(metrics: dict[str, Any]) -> dict[str, float]:
    """Scalar metrics only (for tables / statistics)."""
    out: dict[str, float] = {}
    for group, vals in metrics.items():
        for k, v in vals.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                out[f"{group}.{k}"] = float(v) if v is not None else float("nan")
            elif v is None:
                out[f"{group}.{k}"] = float("nan")
    return out
