#!/usr/bin/env python3
"""Publication-grade plots from custos-bench JSON/CSV trial exports.

Reads every ``*.json`` under ``--results``, groups trials by
``(mode, topology, regime, rps)`` parsed from the label, and writes:

* latency CDF curves from P50 through P99.99 with a 95% CI ribbon
* throughput bar charts (mean offered vs achieved, 95% CI)
* CPU and RSS utilization bars when process samples are present

matplotlib is imported lazily so this file can be syntax-checked without
the plotting extra installed.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path


PERCENTILE_KEYS = ("p50", "p90", "p95", "p99", "p99.9", "p99.99")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True, help="directory of trial JSON files")
    parser.add_argument("--out", type=Path, required=True, help="directory for PNG/PDF figures")
    parser.add_argument("--title", default="Custos admission benchmark")
    return parser.parse_args()


def load_trials(results: Path) -> list[dict]:
    trials = []
    for path in sorted(results.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if "latency" not in payload:
            continue
        payload["_path"] = str(path)
        payload["_group"] = group_key(payload)
        trials.append(payload)
    return trials


def group_key(trial: dict) -> str:
    label = str(trial.get("label", "trial"))
    parts = label.split("_")
    # mode_topology_regime_rpsN_tK  (regime may itself contain hyphens, not underscores)
    if len(parts) >= 4:
        return "_".join(parts[:-1])
    return f"{trial.get('regime', 'unknown')}_rps{trial.get('rps', 0)}"


def percentile_map(summary: dict | None) -> dict[str, float]:
    if not summary:
        return {}
    return {point["label"]: float(point["ns"]) for point in summary.get("percentiles_ns", [])}


def mean_ci(values: list[float]) -> tuple[float, float, float]:
    """Return (mean, low, high) for a 95% Student-t interval.

    Falls back to the sample itself when n < 2. The t critical value for
    95% is approximated for small n; n >= 30 uses 1.96.
    """
    if not values:
        return (0.0, 0.0, 0.0)
    mean = statistics.fmean(values)
    if len(values) < 2:
        return (mean, mean, mean)
    stdev = statistics.stdev(values)
    n = len(values)
    tcrit = _t_crit_95(n - 1)
    half = tcrit * stdev / math.sqrt(n)
    return (mean, mean - half, mean + half)


def _t_crit_95(df: int) -> float:
    table = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 8: 2.306, 10: 2.228, 20: 2.086}
    if df in table:
        return table[df]
    if df >= 30:
        return 1.960
    # Linear interpolation across the tabulated degrees of freedom.
    keys = sorted(table)
    lower = max(k for k in keys if k <= df)
    upper = min(k for k in keys if k >= df)
    if lower == upper:
        return table[lower]
    span = (df - lower) / (upper - lower)
    return table[lower] + span * (table[upper] - table[lower])


def ns_to_ms(value: float) -> float:
    return value / 1_000_000.0


def plot(trials: list[dict], out_dir: Path, title: str) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out_dir.mkdir(parents=True, exist_ok=True)
    grouped: dict[str, list[dict]] = defaultdict(list)
    for trial in trials:
        grouped[trial["_group"]].append(trial)

    fig, ax = plt.subplots(figsize=(8.0, 4.8))
    for name, members in sorted(grouped.items()):
        xs = list(range(len(PERCENTILE_KEYS)))
        series = []
        for key in PERCENTILE_KEYS:
            samples = [percentile_map(m.get("latency")).get(key, 0.0) for m in members]
            series.append(mean_ci([ns_to_ms(s) for s in samples]))
        means = [item[0] for item in series]
        lows = [item[1] for item in series]
        highs = [item[2] for item in series]
        ax.plot(xs, means, marker="o", label=name)
        ax.fill_between(xs, lows, highs, alpha=0.15)
    ax.set_xticks(list(range(len(PERCENTILE_KEYS))))
    ax.set_xticklabels(PERCENTILE_KEYS)
    ax.set_ylabel("Latency (ms)")
    ax.set_xlabel("Percentile")
    ax.set_title(f"{title}: latency CDF (P50–P99.99, 95% CI)")
    ax.set_yscale("log")
    ax.grid(True, which="both", linestyle=":", linewidth=0.6)
    ax.legend(fontsize=7, loc="upper left")
    fig.tight_layout()
    fig.savefig(out_dir / "latency_cdf.png", dpi=200)
    fig.savefig(out_dir / "latency_cdf.pdf")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8.0, 4.8))
    labels = []
    means = []
    errors = []
    for name, members in sorted(grouped.items()):
        stats = mean_ci([float(m.get("achieved_rps", 0.0)) for m in members])
        labels.append(name)
        means.append(stats[0])
        errors.append((stats[0] - stats[1], stats[2] - stats[0]))
    if labels:
        yerr = list(zip(*errors)) if errors else None
        ax.bar(range(len(labels)), means, yerr=yerr, capsize=3, color="#3C6E71")
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=7)
    ax.set_ylabel("Achieved throughput (req/s)")
    ax.set_title(f"{title}: throughput (mean, 95% CI)")
    ax.grid(True, axis="y", linestyle=":", linewidth=0.6)
    fig.tight_layout()
    fig.savefig(out_dir / "throughput.png", dpi=200)
    fig.savefig(out_dir / "throughput.pdf")
    plt.close(fig)

    _plot_resources(grouped, out_dir, title, plt)


def _plot_resources(grouped: dict[str, list[dict]], out_dir: Path, title: str, plt) -> None:
    labels = []
    cpu = []
    rss = []
    for name, members in sorted(grouped.items()):
        cpu_samples = []
        rss_samples = []
        for member in members:
            for proc in member.get("processes", []):
                cpu_samples.append(float(proc.get("peak_cpu_percent", 0.0)))
                rss_samples.append(float(proc.get("peak_rss_kb", 0.0)) / 1024.0)
        if not cpu_samples:
            continue
        labels.append(name)
        cpu.append(mean_ci(cpu_samples)[0])
        rss.append(mean_ci(rss_samples)[0])
    if not labels:
        return
    fig, axes = plt.subplots(1, 2, figsize=(10.0, 4.4))
    axes[0].bar(range(len(labels)), cpu, color="#D1495B")
    axes[0].set_title("Peak CPU %")
    axes[1].bar(range(len(labels)), rss, color="#EDAE49")
    axes[1].set_title("Peak RSS (MiB)")
    for ax in axes:
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=7)
        ax.grid(True, axis="y", linestyle=":", linewidth=0.6)
    fig.suptitle(f"{title}: host utilization")
    fig.tight_layout()
    fig.savefig(out_dir / "utilization.png", dpi=200)
    fig.savefig(out_dir / "utilization.pdf")
    plt.close(fig)


def main() -> int:
    args = parse_args()
    trials = load_trials(args.results)
    if not trials:
        print(f"no trial JSON found under {args.results}")
        return 1
    plot(trials, args.out, args.title)
    print(f"wrote figures for {len(trials)} trials to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
