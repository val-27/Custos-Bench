#!/usr/bin/env python3
"""Pre-registered paired-probe efficacy scorer for Custos-Bench.

Joins client probe observations (``*.probes.jsonl`` or ``TrialReport.probes``)
with Envoy JSON access logs (``--envoy-logs``) and ``custos-proc`` JSON tracing
logs (``--custos-logs``) on ``request_id``, applies the pre-registered
hypothesis and decision rules (H1, H2, H3), and writes
``results/<study>/score/efficacy_pairs.csv`` and ``efficacy_summary.json``.

Refuses to score if:
- any trial report in the study directory has ``study_meta.backend != "triton"``
- ``synthesizer/lint_pairs.py`` reports any corpus lint error
- any eligible pair from ``corpus/manifest.json`` is missing from the study output.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "synthesizer"))
from lint_pairs import lint_corpus  # noqa: E402

ADMISSION_REJECT_STATUSES = {"INVALID_ARGUMENT", "HTTP_400", "PERMISSION_DENIED"}
ELIGIBLE_A_HARM_OR_ACCEPT_STATUSES = {
    "OK",
    "INTERNAL",
    "UNAVAILABLE",
    "TRANSPORT",
    "DEADLINE_EXCEEDED",
    "OTHER",
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--study-dir",
        type=Path,
        required=True,
        help="Study directory (e.g. results/cloud-loopback) containing client/, envoy/, custos/",
    )
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "corpus",
        help="Path to corpus directory containing manifest.json",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=5,
        help="Expected number of trials per cell (default: 5)",
    )
    return parser.parse_args(argv)


def parse_upstream_bytes(val: object, upstream_host: object) -> int | None:
    """Parse Envoy ``upstream_wire_bytes_sent`` from JSON access log.

    When Envoy responds locally via ``ext_proc`` ``ImmediateResponse`` with no upstream
    connection, ``upstream_host`` is empty/``"-"``/``None`` and ``upstream_wire_bytes_sent``
    is ``0``, ``"0"``, ``"-"``, or ``None`` -> returns ``0``.
    """
    host_str = "" if upstream_host is None else str(upstream_host).strip()
    if val is None or val == "-" or val == "":
        if not host_str or host_str == "-":
            return 0
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def load_envoy_logs(study_dir: Path) -> dict[str, dict]:
    """Index Envoy JSON access log lines by ``request_id``."""
    by_req_id: dict[str, dict] = {}
    envoy_dir = study_dir / "envoy"
    search_paths = list(envoy_dir.rglob("*.log")) + list(envoy_dir.rglob("*.jsonl")) if envoy_dir.is_dir() else []
    search_paths += list(study_dir.glob("envoy*.log")) + list(study_dir.glob("envoy*.jsonl"))
    for path in sorted(set(search_paths)):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            req_id = obj.get("request_id")
            if isinstance(req_id, str) and req_id.startswith("t"):
                by_req_id[req_id] = obj
    return by_req_id


def load_custos_logs(study_dir: Path) -> dict[str, dict]:
    """Index ``custos-proc`` JSON log lines by ``request_id``."""
    by_req_id: dict[str, dict] = {}
    custos_dir = study_dir / "custos"
    search_paths = list(custos_dir.rglob("*.log")) + list(custos_dir.rglob("*.jsonl")) if custos_dir.is_dir() else []
    search_paths += list(study_dir.glob("custos*.log")) + list(study_dir.glob("custos*.jsonl"))
    for path in sorted(set(search_paths)):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            # tracing-subscriber JSON format puts fields either at top-level or inside "fields"
            fields = obj.get("fields") if isinstance(obj.get("fields"), dict) else obj
            req_id = fields.get("request_id") or obj.get("request_id")
            decision = fields.get("decision") or obj.get("decision")
            if isinstance(req_id, str) and req_id.startswith("t") and decision in ("ALLOW", "DENY"):
                by_req_id[req_id] = {
                    "request_id": req_id,
                    "decision": decision,
                    "error_code": fields.get("error_code") or obj.get("error_code") or "",
                    "grpc_path": fields.get("grpc_path") or obj.get("grpc_path") or "",
                }
    return by_req_id


def load_client_probes(study_dir: Path) -> tuple[list[dict], list[dict], list[str]]:
    """Return ``(probes, background_reports, errors)``."""
    errors: list[str] = []
    probes: list[dict] = []
    bg_reports: list[dict] = []

    client_dir = study_dir / "client"
    json_files = sorted(client_dir.rglob("*.json")) if client_dir.is_dir() else sorted(study_dir.glob("*.json"))
    for path in json_files:
        if path.name in ("efficacy_summary.json", "latest_results.json"):
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(report, dict) or report.get("regime") != "paired-probe":
            continue
        meta = report.get("study_meta") or {}
        backend = str(meta.get("backend", ""))
        if backend != "triton":
            errors.append(
                f"{path.name}: study_meta.backend is {backend!r}; refusing to score non-triton run"
            )
        bg_reports.append(report)
        for p in report.get("probes") or []:
            probes.append(p)

    return (probes, bg_reports, errors)


def score_single_trial_pair(
    obs_by_role_topo: dict[tuple[str, str], dict],
    envoy_logs: dict[str, dict],
    custos_logs: dict[str, dict],
) -> str:
    """Apply the pre-registered H1, H2, H3 decision table to one ``(cell, pair_id, trial)``."""
    required = [
        ("attack", "A"),
        ("attack", "B"),
        ("attack", "C"),
        ("twin", "A"),
        ("twin", "B"),
        ("twin", "C"),
    ]
    for key in required:
        if key not in obs_by_role_topo:
            return "inconclusive"

    atk_a = obs_by_role_topo[("attack", "A")]
    atk_b = obs_by_role_topo[("attack", "B")]
    atk_c = obs_by_role_topo[("attack", "C")]
    twn_a = obs_by_role_topo[("twin", "A")]
    twn_b = obs_by_role_topo[("twin", "B")]
    twn_c = obs_by_role_topo[("twin", "C")]

    # Join Envoy logs on B and C, and Custos logs on C
    env_atk_b = envoy_logs.get(atk_b["request_id"])
    env_atk_c = envoy_logs.get(atk_c["request_id"])
    env_twn_b = envoy_logs.get(twn_b["request_id"])
    env_twn_c = envoy_logs.get(twn_c["request_id"])
    cus_atk_c = custos_logs.get(atk_c["request_id"])
    cus_twn_c = custos_logs.get(twn_c["request_id"])

    if not all([env_atk_b, env_atk_c, env_twn_b, env_twn_c]):
        return "inconclusive"

    b_atk_up_bytes = parse_upstream_bytes(
        env_atk_b.get("upstream_wire_bytes_sent"), env_atk_b.get("upstream_host")
    )
    c_atk_up_bytes = parse_upstream_bytes(
        env_atk_c.get("upstream_wire_bytes_sent"), env_atk_c.get("upstream_host")
    )
    b_twn_up_bytes = parse_upstream_bytes(
        env_twn_b.get("upstream_wire_bytes_sent"), env_twn_b.get("upstream_host")
    )
    c_twn_up_bytes = parse_upstream_bytes(
        env_twn_c.get("upstream_wire_bytes_sent"), env_twn_c.get("upstream_host")
    )

    if any(x is None for x in (b_atk_up_bytes, c_atk_up_bytes, b_twn_up_bytes, c_twn_up_bytes)):
        return "inconclusive"

    # Transport failure on any twin is inconclusive
    if any(t["status"] == "TRANSPORT" for t in (twn_a, twn_b, twn_c)):
        return "inconclusive"

    # Check fail_open first: Attack on C returns OK, or C upstream bytes > 0
    if atk_c["status"] == "OK" or (c_atk_up_bytes or 0) > 0:
        return "fail_open"

    # Zero upstream bytes on C with no Custos DENY line (e.g. ext_proc timeout) is inconclusive
    if cus_atk_c is None or cus_atk_c.get("decision") != "DENY":
        return "inconclusive"

    # Check false_positive: Twin rejected on C, or twin upstream bytes on C == 0, or Custos did not ALLOW twin
    if (
        twn_c["status"] != "OK"
        or (c_twn_up_bytes or 0) <= 0
        or cus_twn_c is None
        or cus_twn_c.get("decision") != "ALLOW"
    ):
        return "false_positive"

    # Twin must also pass on A and B with B upstream bytes > 0 (H3)
    h3 = (
        twn_a["status"] == "OK"
        and twn_b["status"] == "OK"
        and twn_c["status"] == "OK"
        and (b_twn_up_bytes or 0) > 0
        and (c_twn_up_bytes or 0) > 0
    )
    if not h3:
        return "inconclusive"

    # Proxy effect: B sends 0 upstream bytes (meaning Envoy blocked the attack locally without forwarding to Triton),
    # OR B returned an admission reject that Triton itself (A) did NOT return.
    if (b_atk_up_bytes or 0) == 0 or (
        atk_b["status"] in ADMISSION_REJECT_STATUSES
        and atk_a["status"] not in ADMISSION_REJECT_STATUSES
    ):
        return "proxy_effect"

    # H1: On C the attack client status is in ADMISSION_REJECT_STATUSES, Envoy upstream_host is empty/"-",
    # upstream_wire_bytes_sent == 0, and custos-proc logged decision == DENY.
    c_host = str(env_atk_c.get("upstream_host") or "").strip()
    h1 = (
        atk_c["status"] in ADMISSION_REJECT_STATUSES
        and (not c_host or c_host == "-")
        and c_atk_up_bytes == 0
        and cus_atk_c.get("decision") == "DENY"
    )
    if not h1:
        return "inconclusive"

    # Parser disagreement: A and C both return an admission reject (e.g., INVALID_ARGUMENT) and A stays live
    if atk_a["status"] in ADMISSION_REJECT_STATUSES:
        return "parser_disagreement"

    # H2: On A the attack does not produce that same admission reject (e.g. OK, INTERNAL, UNAVAILABLE, TRANSPORT, DEADLINE_EXCEEDED)
    if atk_a["status"] in ELIGIBLE_A_HARM_OR_ACCEPT_STATUSES:
        return "efficacious"

    return "inconclusive"


def aggregate_trial_labels(trial_labels: list[str], expected_trials: int) -> str:
    """A pair receives a deterministic label at a cell only when all N trials agree."""
    if len(trial_labels) != expected_trials:
        return "inconclusive"
    unique = set(trial_labels)
    if len(unique) == 1:
        return trial_labels[0]
    return "inconclusive"


def score_study(study_dir: Path, corpus_dir: Path, expected_trials: int) -> tuple[dict, int]:
    eligible_pairs, ineligible_rejects, lint_errors, manifest_sha = lint_corpus(corpus_dir)
    if lint_errors:
        for err in lint_errors:
            print(f"corpus lint error: {err}", file=sys.stderr)
        return ({"errors": lint_errors}, 2)

    probes, bg_reports, load_errors = load_client_probes(study_dir)
    if load_errors:
        for err in load_errors:
            print(f"study validation error: {err}", file=sys.stderr)
        return ({"errors": load_errors}, 2)

    if not probes:
        err = f"no paired-probe observations found under {study_dir}"
        print(err, file=sys.stderr)
        return ({"errors": [err]}, 2)

    envoy_logs = load_envoy_logs(study_dir)
    custos_logs = load_custos_logs(study_dir)

    # Index probes by (cell, pair_id, trial) -> (role, topology) -> obs
    grouped: dict[tuple[str, str, int], dict[tuple[str, str], dict]] = defaultdict(dict)
    cells_seen: set[str] = set()
    for p in probes:
        cell = str(p["cell"])
        pair_id = str(p["pair_id"])
        trial = int(p["trial"])
        role = str(p["role"])
        topo = str(p["topology"])
        cells_seen.add(cell)
        grouped[(cell, pair_id, trial)][(role, topo)] = p

    if not cells_seen:
        return ({"errors": ["no cells found in probe observations"]}, 2)

    pair_rows: list[dict] = []
    missing_pairs: list[str] = []
    counts_by_cell: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for cell in sorted(cells_seen):
        for pair in eligible_pairs:
            pid = pair["pair_id"]
            trial_outcomes: list[str] = []
            for t in range(1, expected_trials + 1):
                obs_map = grouped.get((cell, pid, t))
                if not obs_map:
                    missing_pairs.append(f"{cell}:{pid}:t{t}")
                    trial_outcomes.append("inconclusive")
                else:
                    trial_outcomes.append(
                        score_single_trial_pair(obs_map, envoy_logs, custos_logs)
                    )
            final_label = aggregate_trial_labels(trial_outcomes, expected_trials)
            counts_by_cell[cell][final_label] += 1
            pair_rows.append(
                {
                    "cell": cell,
                    "pair_id": pid,
                    "family": pair["family"],
                    "attack": pair["attack"],
                    "twin": pair["twin"],
                    "mutation": pair["mutation"],
                    "trial_1": trial_outcomes[0] if len(trial_outcomes) >= 1 else "inconclusive",
                    "trial_2": trial_outcomes[1] if len(trial_outcomes) >= 2 else "inconclusive",
                    "trial_3": trial_outcomes[2] if len(trial_outcomes) >= 3 else "inconclusive",
                    "trial_4": trial_outcomes[3] if len(trial_outcomes) >= 4 else "inconclusive",
                    "trial_5": trial_outcomes[4] if len(trial_outcomes) >= 5 else "inconclusive",
                    "final_label": final_label,
                }
            )

    score_dir = study_dir / "score"
    score_dir.mkdir(parents=True, exist_ok=True)
    csv_path = score_dir / "efficacy_pairs.csv"
    fieldnames = [
        "cell",
        "pair_id",
        "family",
        "attack",
        "twin",
        "mutation",
        "trial_1",
        "trial_2",
        "trial_3",
        "trial_4",
        "trial_5",
        "final_label",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(pair_rows)

    summary = {
        "manifest_sha256": manifest_sha,
        "eligible_pair_count": len(eligible_pairs),
        "ineligible_reject_count": len(ineligible_rejects),
        "expected_trials": expected_trials,
        "cells": {cell: dict(counts) for cell, counts in sorted(counts_by_cell.items())},
        "missing_observations": missing_pairs,
        "pairs": pair_rows,
        "ineligible_rejects": ineligible_rejects,
    }
    (score_dir / "efficacy_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )

    for cell, counts in sorted(counts_by_cell.items()):
        eff = counts.get("efficacious", 0)
        dis = counts.get("parser_disagreement", 0)
        fp = counts.get("false_positive", 0)
        fo = counts.get("fail_open", 0)
        pe = counts.get("proxy_effect", 0)
        inc = counts.get("inconclusive", 0)
        print(
            f"cell={cell:<12} efficacious={eff}/{len(eligible_pairs)}  "
            f"parser_disagreement={dis}  false_positive={fp}  fail_open={fo}  "
            f"proxy_effect={pe}  inconclusive={inc}"
        )
    print(f"wrote {csv_path}")

    return (summary, 1 if missing_pairs else 0)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    _, code = score_study(args.study_dir, args.corpus_dir, args.trials)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
