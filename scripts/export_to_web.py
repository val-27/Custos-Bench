#!/usr/bin/env python3
"""Transform and aggregate custos-bench TrialReport JSON files for Custos-Web.

Reads raw ``custos-bench`` JSON exports under ``--results``, aggregates multi-trial
groups ``(mode, topology, regime, rps)`` into the flat ``Custos-Web`` dashboard
schema, writes ``telemetry-trials.json``, and optionally updates ``REFERENCE_TRIALS``
in ``Custos-Web/app.js``.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

TOPOLOGY_MAP = {
    "control": "Unprotected Control",
    "baseline": "Proxy Baseline",
    "prod": "Custos Production",
    "custos": "Custos Production",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True, help="Directory containing custos-bench *.json files")
    parser.add_argument("--web-dir", type=Path, required=True, help="Path to Custos-Web directory")
    parser.add_argument("--update-app-js", action="store_true", help="Also bake aggregated trials into Custos-Web/app.js")
    return parser.parse_args()


def infer_topology(label: str) -> str:
    lower = label.lower()
    for key, display in TOPOLOGY_MAP.items():
        if f"_{key}_" in lower or lower.startswith(f"{key}_"):
            return display
    return "Custos Production"


def infer_benign_profile(label: str, regime: str) -> str:
    lower = label.lower()
    if "_bytes_" in lower:
        return "BYTES Tensor [1, 2]"
    if "_mixed_" in lower or regime in ("interleaved", "saturating-burst"):
        return "Mixed (FP32 + BYTES + D≤16)"
    return "ResNet-50 B=1 (FP32)"


def group_key(raw: dict) -> tuple[str, str, str, int]:
    label = str(raw.get("label", ""))
    topo = infer_topology(label)
    regime = str(raw.get("regime", "interleaved"))
    profile = infer_benign_profile(label, regime)
    rps = int(raw.get("rps", 0))
    return (topo, regime, profile, rps)


def extract_percentiles_ms(raw: dict) -> dict[str, float]:
    benign_lat = raw.get("benign_latency") or {}
    latency = benign_lat if int(benign_lat.get("count", 0)) > 0 else (raw.get("latency") or {})
    pts = {p["label"]: float(p["ns"]) / 1_000_000.0 for p in latency.get("percentiles_ns", [])}
    return {
        "p50_ms": round(pts.get("p50", 0.0), 3),
        "p90_ms": round(pts.get("p90", 0.0), 3),
        "p95_ms": round(pts.get("p95", 0.0), 3),
        "p99_ms": round(pts.get("p99", 0.0), 3),
        "p999_ms": round(pts.get("p99.9", 0.0), 3),
        "p9999_ms": round(pts.get("p99.99", 0.0), 3),
    }


def extract_resources(raw: dict) -> tuple[float, float]:
    procs = raw.get("processes") or []
    if procs:
        cpu_1k = sum(float(p.get("cpu_per_1000_requests_percent", 0.0)) for p in procs)
        rss_mb = sum(float(p.get("peak_rss_kb", 0.0)) for p in procs) / 1024.0
        return (round(cpu_1k, 2), round(rss_mb, 2))
    return (0.0, 0.0)


def build_survival_verdict(
    topo: str,
    regime: str,
    tp_drop: float | None,
    internal_faults: int,
    baseline_p50: float | None,
    p50: float,
    p99: float = 0.0,
    unique_malicious_sent: int = 0,
    unique_malicious_rejected: int = 0,
    benign_sent: int = 0,
    benign_ok: int = 0,
) -> str:
    benign_failed = max(0, benign_sent - benign_ok) if benign_sent > 0 else 0
    if regime == "steady-benign":
        if benign_failed > 0:
            return f"Degraded ({benign_ok}/{benign_sent} Benign OK)"
        if topo == "Unprotected Control":
            return "Control Floor (No Attack)"
        if topo == "Proxy Baseline":
            return "Hardened Envoy Baseline (No Attack)"
        if baseline_p50 is not None and baseline_p50 > 0:
            delta_us = (p50 - baseline_p50) * 1000.0
            sign = "+" if delta_us >= 0 else ""
            return f"100% Healthy ({sign}{delta_us:.0f} µs P50 vs Baseline)"
        return "100% Healthy (0% False Positives)"

    if regime == "interleaved":
        if (
            topo == "Custos Production"
            and (tp_drop or 0.0) >= 0.999
            and unique_malicious_sent > 0
            and unique_malicious_rejected == unique_malicious_sent
            and benign_failed == 0
        ):
            return f"100% Protected ({unique_malicious_rejected}/{unique_malicious_sent} Exploits Dropped)"
        if benign_failed > 0:
            return f"Degraded ({benign_ok}/{benign_sent} Benign OK, {internal_faults} Backend Faults)"
        if internal_faults > 0:
            return f"Degraded ({internal_faults} Backend Runtime Faults)"
        return f"Degraded ({unique_malicious_rejected}/{unique_malicious_sent} Exploits Dropped)"

    # saturating-burst (90% attack / 10% benign mixed closed fan-out)
    if (
        topo == "Custos Production"
        and (tp_drop or 0.0) >= 0.999
        and benign_sent > 0
        and benign_failed == 0
    ):
        return f"100% Benign Survival ({benign_ok}/{benign_sent} OK, Benign P99 {p99:.1f} ms)"
    if benign_sent > 0 and benign_failed > 0:
        return f"Degraded ({benign_ok}/{benign_sent} Benign OK, Benign P99 {p99:.1f} ms)"
    return f"Backend Flooded (Benign P99 {p99:.1f} ms)"


def normalize_single_trial(raw: dict, baseline_p50: float | None = None) -> dict:
    label = str(raw.get("label", "trial"))
    topo = infer_topology(label)
    regime = str(raw.get("regime", "interleaved"))
    benign_profile = infer_benign_profile(label, regime)
    rps = int(raw.get("rps", 0))
    if rps == 0 and regime == "saturating-burst":
        rps = int(raw.get("requests_requested", 500))
    achieved_rps = round(float(raw.get("achieved_rps", 0.0)), 2)
    acc = raw.get("accuracy") or {}
    fpr = round(float(acc.get("false_positive_rate", 0.0)), 6)
    tp_drop = None if regime == "steady-benign" else round(float(acc.get("true_positive_drop_rate", 0.0)), 6)
    benign_sent = int(acc.get("benign_sent", 0))
    benign_ok = int(acc.get("benign_ok", benign_sent))
    unique_mal_sent = int(acc.get("unique_malicious_sent", acc.get("malicious_sent", 0)))
    unique_mal_rej = int(acc.get("unique_malicious_rejected", acc.get("malicious_rejected", 0)))
    status = raw.get("status") or {}
    internal_faults = int(status.get("internal", 0))
    pcts = extract_percentiles_ms(raw)
    cpu_per_1k, rss_mb = extract_resources(raw)
    survival = build_survival_verdict(
        topo,
        regime,
        tp_drop,
        internal_faults,
        baseline_p50,
        pcts["p50_ms"],
        pcts["p99_ms"],
        unique_mal_sent,
        unique_mal_rej,
        benign_sent,
        benign_ok,
    )

    return {
        "label": label,
        "topology": topo,
        "regime": regime,
        "benign_profile": benign_profile,
        "rps": rps,
        "achieved_rps": achieved_rps,
        "fpr": fpr,
        "tp_drop": tp_drop,
        **pcts,
        "cpu_per_1k": cpu_per_1k,
        "rss_mb": rss_mb,
        "survival": survival,
    }


def aggregate_trials(raw_trials: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str, str, int], list[dict]] = defaultdict(list)
    for raw in raw_trials:
        if "latency" not in raw:
            continue
        groups[group_key(raw)].append(raw)

    # First pass to compute mean P50 for Proxy Baseline in steady-benign per (profile, rps)
    baseline_p50_by_key: dict[tuple[str, int], float] = {}
    for (topo, regime, profile, rps), members in groups.items():
        if topo == "Proxy Baseline" and regime == "steady-benign":
            p50s = [extract_percentiles_ms(m)["p50_ms"] for m in members]
            baseline_p50_by_key[(profile, rps)] = statistics.fmean(p50s)

    topo_order = {"Unprotected Control": 0, "Proxy Baseline": 1, "Custos Production": 2}
    regime_order = {"steady-benign": 0, "interleaved": 1, "saturating-burst": 2}
    profile_order = {
        "ResNet-50 B=1 (FP32)": 0,
        "BYTES Tensor [1, 2]": 1,
        "Mixed (FP32 + BYTES + D≤16)": 2,
    }

    aggregated = []
    for (topo, regime, profile, rps), members in sorted(
        groups.items(),
        key=lambda item: (
            regime_order.get(item[0][1], 9),
            profile_order.get(item[0][2], 9),
            item[0][3],
            topo_order.get(item[0][0], 9),
        ),
    ):
        base_p50 = baseline_p50_by_key.get((profile, rps))
        normed = [normalize_single_trial(m, base_p50) for m in members]
        first = normed[0]
        mean_p50 = round(statistics.fmean(n["p50_ms"] for n in normed), 2)
        mean_p90 = round(statistics.fmean(n["p90_ms"] for n in normed), 2)
        mean_p95 = round(statistics.fmean(n["p95_ms"] for n in normed), 2)
        mean_p99 = round(statistics.fmean(n["p99_ms"] for n in normed), 2)
        mean_p999 = round(statistics.fmean(n["p999_ms"] for n in normed), 2)
        mean_p9999 = round(statistics.fmean(n["p9999_ms"] for n in normed), 2)
        mean_achieved = round(statistics.fmean(n["achieved_rps"] for n in normed), 1)
        mean_fpr = round(statistics.fmean(n["fpr"] for n in normed), 6)
        tp_vals = [n["tp_drop"] for n in normed if n["tp_drop"] is not None]
        mean_tp_drop = None if regime == "steady-benign" or not tp_vals else round(statistics.fmean(tp_vals), 6)
        total_internal = sum(int((m.get("status") or {}).get("internal", 0)) for m in members)
        mean_cpu_1k = round(statistics.fmean(n["cpu_per_1k"] for n in normed), 2)
        mean_rss_mb = round(statistics.fmean(n["rss_mb"] for n in normed), 2)
        accs = [m.get("accuracy") or {} for m in members]
        min_unique_sent = min((int(a.get("unique_malicious_sent", a.get("malicious_sent", 0))) for a in accs), default=0)
        min_unique_rej = min((int(a.get("unique_malicious_rejected", a.get("malicious_rejected", 0))) for a in accs), default=0)
        total_benign_sent = sum(int(a.get("benign_sent", 0)) for a in accs)
        total_benign_ok = sum(int(a.get("benign_ok", a.get("benign_sent", 0))) for a in accs)
        survival = build_survival_verdict(
            topo,
            regime,
            mean_tp_drop,
            total_internal // len(members),
            base_p50,
            mean_p50,
            mean_p99,
            min_unique_sent,
            min_unique_rej,
            total_benign_sent,
            total_benign_ok,
        )

        short_topo = "control" if "Control" in topo else ("baseline" if "Baseline" in topo else "prod")
        prof_slug = "bytes" if "BYTES Tensor" in profile else ("mixed" if "Mixed" in profile else "fp32")
        aggregated.append(
            {
                "label": f"homelab_{short_topo}_{regime}_{prof_slug}_rps{first['rps']}_mean_n{len(members)}",
                "topology": topo,
                "regime": regime,
                "benign_profile": profile,
                "rps": first["rps"],
                "achieved_rps": mean_achieved,
                "fpr": mean_fpr,
                "tp_drop": mean_tp_drop,
                "p50_ms": mean_p50,
                "p90_ms": mean_p90,
                "p95_ms": mean_p95,
                "p99_ms": mean_p99,
                "p999_ms": mean_p999,
                "p9999_ms": mean_p9999,
                "cpu_per_1k": mean_cpu_1k,
                "rss_mb": mean_rss_mb,
                "survival": survival,
                "trials_merged": len(members),
            }
        )
    return aggregated


def main() -> int:
    args = parse_args()

    raw_trials = []
    for path in sorted(args.results.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if str(payload.get("regime", "")) == "oracle-sweep":
            continue
        if "latency" in payload:
            raw_trials.append(payload)

    if not raw_trials:
        print(f"No custos-bench trial JSONs found in {args.results}")
        return 1

    aggregated = aggregate_trials(raw_trials)
    print(f"Aggregated {len(aggregated)} trial series (from {len(raw_trials)} raw trials)")

    if args.update_app_js:
        app_js = args.web_dir / "app.js"
        content = app_js.read_text(encoding="utf-8")
        replacement = "const REFERENCE_TRIALS = " + json.dumps(aggregated, indent=2, ensure_ascii=False) + ";"
        new_content, count = re.subn(
            r"const REFERENCE_TRIALS = \[.*?\];",
            lambda _: replacement,
            content,
            count=1,
            flags=re.DOTALL,
        )
        if count == 1:
            app_js.write_text(new_content, encoding="utf-8")
            print(f"Updated REFERENCE_TRIALS in {app_js}")
        else:
            print(f"Warning: could not locate REFERENCE_TRIALS block in {app_js}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
