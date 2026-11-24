#!/usr/bin/env python3
"""Aggregate arbitrary numbers of custos-bench trials (e.g., N=5 up to N=1,000+ runs).

Reads raw ``custos-bench`` ``*.json`` trial exports under ``--results``, groups them
by ``(topology, regime, benign_profile, rps)``, and computes:

* Pooled request-level accuracy across all runs:
  - Total benign requests sent, admitted, and rejected
  - Pooled False Positive Rate (FPR) and exact 95% Clopper-Pearson upper bound
  - Total malicious requests sent and rejected, plus pooled True Positive Drop Rate
* Per-group latency distribution across N trials for P50, P90, P95, P99, P99.9, P99.99:
  - Mean, sample standard deviation (SD), 95% Student-t / normal confidence interval (CI95),
    median, interquartile range (IQR), min, and max
* Per-process resource breakdown (CPU % per 1,000 requests and Peak RSS MiB per daemon
  so Envoy, custos-proc, and tritonserver costs are reported separately as well as summed)
* Optional JSON, CSV, and Markdown summary table outputs for papers and dashboards.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

from export_to_web import (
    build_oracle_sweep_rows,
    extract_percentiles_ms,
    group_key,
    infer_benign_profile,
    infer_topology,
)

PERCENTILE_FIELDS = ("p50_ms", "p90_ms", "p95_ms", "p99_ms", "p999_ms", "p9999_ms")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results",
        type=Path,
        required=True,
        help="Directory containing custos-bench *.json trial files (searched recursively)",
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=None,
        help="Optional path to write full aggregated JSON report",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=None,
        help="Optional path to write flat CSV summary across trial groups",
    )
    parser.add_argument(
        "--out-md",
        type=Path,
        default=None,
        help="Optional path to write Markdown report tables",
    )
    return parser.parse_args(argv)


def t_crit_95(df: int) -> float:
    """Two-sided 95% Student-t critical value (converges to 1.960 for large N)."""
    table = {
        1: 12.706,
        2: 4.303,
        3: 3.182,
        4: 2.776,
        5: 2.571,
        6: 2.447,
        7: 2.365,
        8: 2.306,
        9: 2.262,
        10: 2.228,
        15: 2.131,
        20: 2.086,
        25: 2.060,
        30: 2.042,
        40: 2.021,
        60: 2.000,
        120: 1.980,
    }
    if df <= 0:
        return 0.0
    if df in table:
        return table[df]
    if df > 120:
        return 1.95996
    keys = sorted(table)
    low = max(k for k in keys if k <= df)
    high = min(k for k in keys if k >= df)
    if low == high:
        return table[low]
    frac = (df - low) / (high - low)
    return table[low] + frac * (table[high] - table[low])


def clopper_pearson_upper_95(k: int, n: int) -> float:
    """Upper 95% confidence bound (one-sided 95% / two-sided 90%, or exact k=0 rule-of-3).

    For k == 0, the exact two-sided 95% Clopper-Pearson upper bound (alpha/2 = 0.025)
    is ``1 - (0.025) ** (1 / n)``. For k > 0, uses a normal/Wilson approximation.
    """
    if n <= 0:
        return 0.0
    if k <= 0:
        return 1.0 - math.pow(0.025, 1.0 / n)
    if k >= n:
        return 1.0
    # Wilson score 95% upper bound for k > 0
    z = 1.95996
    p = k / n
    denom = 1.0 + (z * z) / n
    center = p + (z * z) / (2.0 * n)
    half = z * math.sqrt((p * (1.0 - p) / n) + (z * z) / (4.0 * n * n))
    return min(1.0, (center + half) / denom)


def summarize_metric(values: list[float]) -> dict[str, float]:
    """Compute mean, sd, ci95_half, ci95_low, ci95_high, median, iqr, min, max."""
    if not values:
        return {
            "mean": 0.0,
            "sd": 0.0,
            "ci95_half": 0.0,
            "ci95_low": 0.0,
            "ci95_high": 0.0,
            "median": 0.0,
            "iqr": 0.0,
            "min": 0.0,
            "max": 0.0,
        }
    n = len(values)
    ordered = sorted(values)
    mean = statistics.fmean(ordered)
    median = statistics.median(ordered)
    sd = statistics.stdev(ordered) if n >= 2 else 0.0
    half = t_crit_95(n - 1) * sd / math.sqrt(n) if n >= 2 else 0.0
    if n >= 4:
        q = statistics.quantiles(ordered, n=4)
        iqr = q[2] - q[0]
    else:
        iqr = ordered[-1] - ordered[0]
    return {
        "mean": round(mean, 3),
        "sd": round(sd, 3),
        "ci95_half": round(half, 3),
        "ci95_low": round(mean - half, 3),
        "ci95_high": round(mean + half, 3),
        "median": round(median, 3),
        "iqr": round(iqr, 3),
        "min": round(ordered[0], 3),
        "max": round(ordered[-1], 3),
    }


def aggregate_runs(results_dir: Path) -> dict:
    raw_trials: list[dict] = []
    oracle_trials: list[dict] = []

    for path in sorted(results_dir.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        if str(payload.get("regime", "")) == "oracle-sweep":
            oracle_trials.append(payload)
            continue
        if "latency" in payload and "accuracy" in payload:
            raw_trials.append(payload)

    groups: dict[tuple[str, str, str, int], list[dict]] = defaultdict(list)
    for raw in raw_trials:
        groups[group_key(raw)].append(raw)

    # Pooled totals by topology across all regimes (including oracle-sweep)
    pooled_by_topology: dict[str, dict] = {}
    for topo in ("Unprotected Control", "Proxy Baseline", "Custos Production"):
        pooled_by_topology[topo] = {
            "trial_files": 0,
            "requests_completed": 0,
            "benign_sent": 0,
            "benign_ok": 0,
            "benign_rejected": 0,
            "malicious_sent": 0,
            "malicious_rejected": 0,
        }

    for raw in raw_trials:
        topo = infer_topology(str(raw.get("label", "")))
        acc = raw.get("accuracy") or {}
        slot = pooled_by_topology[topo]
        slot["trial_files"] += 1
        slot["requests_completed"] += int(raw.get("requests_completed", 0))
        slot["benign_sent"] += int(acc.get("benign_sent", 0))
        slot["benign_ok"] += int(acc.get("benign_ok", 0))
        slot["benign_rejected"] += int(acc.get("benign_rejected", 0))
        slot["malicious_sent"] += int(acc.get("malicious_sent", 0))
        slot["malicious_rejected"] += int(acc.get("malicious_rejected", 0))

    for raw in oracle_trials:
        topo = infer_topology(str(raw.get("label", "")))
        slot = pooled_by_topology[topo]
        slot["trial_files"] += 1
        rows = raw.get("oracle") or []
        slot["requests_completed"] += len(rows)
        for r in rows:
            if r.get("expected") == "allow":
                slot["benign_sent"] += 1
                if r.get("match"):
                    slot["benign_ok"] += 1
                else:
                    slot["benign_rejected"] += 1
            elif r.get("expected") == "reject":
                slot["malicious_sent"] += 1
                if r.get("match"):
                    slot["malicious_rejected"] += 1

    for topo, slot in pooled_by_topology.items():
        bs = slot["benign_sent"]
        br = slot["benign_rejected"]
        ms = slot["malicious_sent"]
        mr = slot["malicious_rejected"]
        slot["pooled_fpr"] = round(br / bs, 8) if bs > 0 else 0.0
        slot["fpr_ci95_upper"] = round(clopper_pearson_upper_95(br, bs), 8)
        slot["fpr_ci95_upper_pct"] = round(clopper_pearson_upper_95(br, bs) * 100.0, 5)
        slot["pooled_tp_drop"] = round(mr / ms, 8) if ms > 0 else 0.0

    topo_order = {"Unprotected Control": 0, "Proxy Baseline": 1, "Custos Production": 2}
    regime_order = {"steady-benign": 0, "interleaved": 1, "saturating-burst": 2}
    profile_order = {
        "ResNet-50 B=1 (FP32)": 0,
        "BYTES Tensor [1, 2]": 1,
        "Mixed (FP32 + BYTES + D≤16)": 2,
    }

    series_list: list[dict] = []
    for (topo, regime, profile, rps), members in sorted(
        groups.items(),
        key=lambda item: (
            regime_order.get(item[0][1], 9),
            profile_order.get(item[0][2], 9),
            item[0][3],
            topo_order.get(item[0][0], 9),
        ),
    ):
        pct_lists: dict[str, list[float]] = {k: [] for k in PERCENTILE_FIELDS}
        rps_vals: list[float] = []
        cpu_sum_vals: list[float] = []
        rss_sum_vals: list[float] = []
        per_proc_rss: dict[str, list[float]] = defaultdict(list)
        per_proc_cpu: dict[str, list[float]] = defaultdict(list)

        total_reqs = 0
        benign_sent = 0
        benign_ok = 0
        benign_rej = 0
        mal_sent = 0
        mal_rej = 0
        internal_faults = 0

        for m in members:
            pcts = extract_percentiles_ms(m)
            for k in PERCENTILE_FIELDS:
                pct_lists[k].append(pcts[k])
            rps_vals.append(float(m.get("achieved_rps", 0.0)))
            procs = m.get("processes") or []
            if procs:
                cpu_sum_vals.append(
                    sum(float(p.get("cpu_per_1000_requests_percent", 0.0)) for p in procs)
                )
                rss_sum_vals.append(
                    sum(float(p.get("peak_rss_kb", 0.0)) for p in procs) / 1024.0
                )
                for p in procs:
                    pname = str(p.get("label", "proc"))
                    per_proc_rss[pname].append(float(p.get("peak_rss_kb", 0.0)) / 1024.0)
                    per_proc_cpu[pname].append(float(p.get("cpu_per_1000_requests_percent", 0.0)))

            total_reqs += int(m.get("requests_completed", 0))
            acc = m.get("accuracy") or {}
            bs = int(acc.get("benign_sent", 0))
            benign_sent += bs
            benign_ok += int(acc.get("benign_ok", bs))
            benign_rej += int(acc.get("benign_rejected", 0))
            mal_sent += int(acc.get("malicious_sent", 0))
            mal_rej += int(acc.get("malicious_rejected", 0))
            internal_faults += int((m.get("status") or {}).get("internal", 0))

        effective_rps = rps
        if effective_rps == 0 and regime == "saturating-burst":
            effective_rps = int(members[0].get("requests_requested", 500))

        proc_breakdown = {}
        for pname in sorted(per_proc_rss):
            proc_breakdown[pname] = {
                "peak_rss_mb_mean": round(statistics.fmean(per_proc_rss[pname]), 2),
                "cpu_per_1k_mean": round(statistics.fmean(per_proc_cpu[pname]), 2),
            }

        series_list.append(
            {
                "topology": topo,
                "regime": regime,
                "benign_profile": profile,
                "rps": effective_rps,
                "trials_merged": len(members),
                "total_requests_completed": total_reqs,
                "benign_sent_total": benign_sent,
                "benign_ok_total": benign_ok,
                "benign_rejected_total": benign_rej,
                "pooled_fpr": round(benign_rej / benign_sent, 8) if benign_sent > 0 else 0.0,
                "fpr_ci95_upper": round(clopper_pearson_upper_95(benign_rej, benign_sent), 8),
                "malicious_sent_total": mal_sent,
                "malicious_rejected_total": mal_rej,
                "pooled_tp_drop": None
                if regime == "steady-benign" or mal_sent == 0
                else round(mal_rej / mal_sent, 8),
                "internal_faults_total": internal_faults,
                "achieved_rps": summarize_metric(rps_vals),
                "p50_ms": summarize_metric(pct_lists["p50_ms"]),
                "p90_ms": summarize_metric(pct_lists["p90_ms"]),
                "p95_ms": summarize_metric(pct_lists["p95_ms"]),
                "p99_ms": summarize_metric(pct_lists["p99_ms"]),
                "p999_ms": summarize_metric(pct_lists["p999_ms"]),
                "p9999_ms": summarize_metric(pct_lists["p9999_ms"]),
                "cpu_per_1k": summarize_metric(cpu_sum_vals),
                "rss_mb": summarize_metric(rss_sum_vals),
                "process_breakdown": proc_breakdown,
            }
        )

    manifest_path = Path(__file__).resolve().parent.parent / "corpus" / "manifest.json"
    oracle_rows = build_oracle_sweep_rows(oracle_trials, manifest_path)

    return {
        "total_trial_files": len(raw_trials) + len(oracle_trials),
        "open_loop_and_burst_files": len(raw_trials),
        "oracle_sweep_files": len(oracle_trials),
        "pooled_by_topology": pooled_by_topology,
        "series": series_list,
        "oracle_sweep": oracle_rows,
    }


def write_csv(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "topology",
        "regime",
        "benign_profile",
        "rps",
        "trials_merged",
        "total_requests_completed",
        "benign_sent_total",
        "benign_rejected_total",
        "pooled_fpr",
        "fpr_ci95_upper",
        "malicious_sent_total",
        "malicious_rejected_total",
        "pooled_tp_drop",
        "achieved_rps_mean",
        "achieved_rps_ci95",
        "p50_ms_mean",
        "p50_ms_ci95",
        "p50_ms_min",
        "p50_ms_max",
        "p99_ms_mean",
        "p99_ms_ci95",
        "p99_ms_min",
        "p99_ms_max",
        "p9999_ms_mean",
        "rss_mb_mean",
        "cpu_per_1k_mean",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for s in report["series"]:
            writer.writerow(
                {
                    "topology": s["topology"],
                    "regime": s["regime"],
                    "benign_profile": s["benign_profile"],
                    "rps": s["rps"],
                    "trials_merged": s["trials_merged"],
                    "total_requests_completed": s["total_requests_completed"],
                    "benign_sent_total": s["benign_sent_total"],
                    "benign_rejected_total": s["benign_rejected_total"],
                    "pooled_fpr": s["pooled_fpr"],
                    "fpr_ci95_upper": s["fpr_ci95_upper"],
                    "malicious_sent_total": s["malicious_sent_total"],
                    "malicious_rejected_total": s["malicious_rejected_total"],
                    "pooled_tp_drop": "" if s["pooled_tp_drop"] is None else s["pooled_tp_drop"],
                    "achieved_rps_mean": s["achieved_rps"]["mean"],
                    "achieved_rps_ci95": s["achieved_rps"]["ci95_half"],
                    "p50_ms_mean": s["p50_ms"]["mean"],
                    "p50_ms_ci95": s["p50_ms"]["ci95_half"],
                    "p50_ms_min": s["p50_ms"]["min"],
                    "p50_ms_max": s["p50_ms"]["max"],
                    "p99_ms_mean": s["p99_ms"]["mean"],
                    "p99_ms_ci95": s["p99_ms"]["ci95_half"],
                    "p99_ms_min": s["p99_ms"]["min"],
                    "p99_ms_max": s["p99_ms"]["max"],
                    "p9999_ms_mean": s["p9999_ms"]["mean"],
                    "rss_mb_mean": s["rss_mb"]["mean"],
                    "cpu_per_1k_mean": s["cpu_per_1k"]["mean"],
                }
            )


def format_markdown(report: dict) -> str:
    lines = [
        "# Custos Multi-Trial Aggregation Report",
        "",
        f"- **Total Trial Files Processed:** `{report['total_trial_files']}` "
        f"(`{report['open_loop_and_burst_files']}` performance runs + `{report['oracle_sweep_files']}` oracle sweeps)",
        "",
        "## 1. Pooled Filtering Accuracy & Clopper-Pearson 95% Upper Bound",
        "",
        "| Topology | Trial Files | Total Requests | Benign Sent | False Positives | Pooled FPR | 95% Upper Bound (Clopper-Pearson) | Attacks Sent | Attacks Blocked | Pooled TP Drop |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for topo, slot in report["pooled_by_topology"].items():
        lines.append(
            f"| **{topo}** | {slot['trial_files']} | {slot['requests_completed']:,} | "
            f"{slot['benign_sent']:,} | {slot['benign_rejected']} | "
            f"{slot['pooled_fpr'] * 100:.4f}% | **<{slot['fpr_ci95_upper_pct']:.4f}%** | "
            f"{slot['malicious_sent']:,} | {slot['malicious_rejected']:,} | "
            f"{slot['pooled_tp_drop'] * 100:.2f}% |"
        )

    lines.extend(
        [
            "",
            "## 2. Multi-Trial Latency & Resource Summary (Mean ± 95% CI, [Min..Max])",
            "",
            "| Topology | Regime | Profile | RPS | N | P50 (ms) | P99 (ms) | P99 Range (ms) | Summed RSS (MiB) | Per-Daemon RSS (MiB) |",
            "| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |",
        ]
    )
    for s in report["series"]:
        p50 = s["p50_ms"]
        p99 = s["p99_ms"]
        rss = s["rss_mb"]
        procs = ", ".join(
            f"{k}={v['peak_rss_mb_mean']:.1f}" for k, v in s["process_breakdown"].items()
        )
        lines.append(
            f"| {s['topology']} | `{s['regime']}` | {s['benign_profile']} | {s['rps']} | "
            f"{s['trials_merged']} | {p50['mean']:.2f} ± {p50['ci95_half']:.2f} | "
            f"{p99['mean']:.2f} ± {p99['ci95_half']:.2f} | "
            f"[{p99['min']:.2f}..{p99['max']:.2f}] | {rss['mean']:.1f} | {procs or 'N/A'} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = aggregate_runs(args.results)
    if report["total_trial_files"] == 0:
        print(f"No custos-bench JSON files found under {args.results}")
        return 1

    md_text = format_markdown(report)
    print(md_text)

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"Wrote JSON aggregation report to {args.out_json}")

    if args.out_csv:
        write_csv(report, args.out_csv)
        print(f"Wrote CSV aggregation summary to {args.out_csv}")

    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(md_text, encoding="utf-8")
        print(f"Wrote Markdown aggregation summary to {args.out_md}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
