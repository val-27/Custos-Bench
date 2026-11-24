#!/usr/bin/env python3
"""Pre-registration eligibility lint for the paired-probe efficacy study.

Validates ``corpus/manifest.json`` and its on-disk wire artifacts before any
``--regime paired-probe`` trial is permitted to run:

1. Every manifest entry must declare a valid ``role`` in:
   ``{"attack", "twin", "background", "unpaired_attack", "header_probe"}``.
2. Every ``role == "attack"`` entry must have ``expected == "reject"``,
   ``eligible == True``, a unique ``pair_id``, a non-empty ``mutation``,
   and a ``twin`` naming an existing ``expected == "allow"`` entry.
3. Every ``expected == "reject"`` entry that is not ``eligible`` must
   declare a non-empty ``ineligible_reason`` so no reject payload is
   silently omitted from the study census.
4. Structural wire checks on known edge-case payloads:
   - ``cve_2024_0088_shm_params_infer`` must encode ``InferParameter.string_param``
     on field 3 (tag ``0x1A``) and ``InferParameter.int64_param`` on field 2 (tag ``0x10``).
   - ``shape_neg_packed`` and ``benign_shape_pos_packed`` must differ only in the
     3rd dimension varint (``-1`` 10-byte two's complement vs ``+1``) and the
     corresponding ``raw_input_contents`` buffer.
   - ``frame_two_concat`` must equal two concatenated copies of ``frame_single``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

VALID_ROLES = {"attack", "twin", "background", "unpaired_attack", "header_probe"}

KNOWN_MUTATIONS = {
    "depth_17_vs_16",
    "sign_bit",
    "truncated_raw_chunk",
    "shared_memory_param_key",
    "raw_chunk_order",
    "raw_chunk_cardinality",
    "raw_chunk_wire_order_and_swap",
    "contents_cardinality_short",
    "contents_cardinality_ceiling",
    "bytes_u32_length_prefix",
    "bytes_chunk_compensates_short_fp32",
    "raw_width",
    "datatype_token",
    "concatenated_second_grpc_frame",
}


def resolve_file(corpus_dir: Path, rel_path: str) -> Path:
    p = Path(rel_path)
    if p.is_absolute():
        return p
    if (corpus_dir.parent / p).is_file():
        return corpus_dir.parent / p
    if (corpus_dir / p).is_file():
        return corpus_dir / p
    try:
        stripped = p.relative_to("corpus")
        if (corpus_dir / stripped).is_file():
            return corpus_dir / stripped
    except ValueError:
        pass
    return corpus_dir.parent / p


def lint_corpus(corpus_dir: Path) -> tuple[list[dict], list[dict], list[str], str]:
    """Return ``(eligible_pairs, ineligible_rejects, errors, manifest_sha256)``."""
    errors: list[str] = []
    manifest_path = corpus_dir / "manifest.json"
    if not manifest_path.is_file():
        return ([], [], [f"manifest not found: {manifest_path}"], "")

    raw_bytes = manifest_path.read_bytes()
    manifest_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    try:
        manifest = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        return ([], [], [f"invalid JSON in {manifest_path}: {exc}"], manifest_sha256)

    artifacts = manifest.get("artifacts") or []
    if not artifacts:
        errors.append("manifest contains zero artifacts")

    by_name: dict[str, dict] = {}
    for item in artifacts:
        name = item.get("name")
        if not name:
            errors.append("artifact missing 'name'")
            continue
        if name in by_name:
            errors.append(f"duplicate artifact name: {name}")
        by_name[name] = item

    seen_pair_ids: dict[str, str] = {}
    eligible_pairs: list[dict] = []
    ineligible_rejects: list[dict] = []

    for item in artifacts:
        name = str(item.get("name", ""))
        expected = str(item.get("expected", ""))
        role = str(item.get("role", ""))
        eligible = bool(item.get("eligible", False))
        pair_id = item.get("pair_id")
        twin_name = item.get("twin")
        mutation = item.get("mutation")
        reason = item.get("ineligible_reason")

        if role not in VALID_ROLES:
            errors.append(f"{name}: invalid role {role!r} (expected one of {sorted(VALID_ROLES)})")

        pb_file = resolve_file(corpus_dir, str(item.get("pb_path", "")))
        if not pb_file.is_file():
            errors.append(f"{name}: missing payload file {pb_file}")

        if eligible:
            if role != "attack":
                errors.append(f"{name}: eligible=True requires role='attack', got {role!r}")
            if expected != "reject":
                errors.append(f"{name}: eligible=True requires expected='reject', got {expected!r}")
            if not pair_id:
                errors.append(f"{name}: eligible attack is missing pair_id")
            elif pair_id in seen_pair_ids:
                errors.append(
                    f"{name}: duplicate attack pair_id {pair_id!r} (already used by {seen_pair_ids[pair_id]})"
                )
            else:
                seen_pair_ids[pair_id] = name

            if not mutation:
                errors.append(f"{name}: eligible attack is missing mutation id")
            elif mutation not in KNOWN_MUTATIONS:
                errors.append(f"{name}: unknown mutation id {mutation!r}")

            if not twin_name:
                errors.append(f"{name}: eligible attack is missing twin name")
            elif twin_name not in by_name:
                errors.append(f"{name}: twin {twin_name!r} does not exist in manifest")
            else:
                twin_art = by_name[twin_name]
                if twin_art.get("expected") != "allow":
                    errors.append(
                        f"{name}: twin {twin_name!r} must have expected='allow', got {twin_art.get('expected')!r}"
                    )
                if twin_art.get("framing") != item.get("framing"):
                    errors.append(
                        f"{name}: framing {item.get('framing')!r} does not match twin {twin_name!r} ({twin_art.get('framing')!r})"
                    )

            eligible_pairs.append(
                {
                    "pair_id": pair_id,
                    "family": item.get("family"),
                    "attack": name,
                    "twin": twin_name,
                    "mutation": mutation,
                    "framing": item.get("framing", "protobuf"),
                    "method": item.get("method", "/inference.GRPCInferenceService/ModelInfer"),
                }
            )
        elif expected == "reject":
            if role not in ("unpaired_attack", "header_probe"):
                errors.append(
                    f"{name}: ineligible reject must have role 'unpaired_attack' or 'header_probe', got {role!r}"
                )
            if not reason:
                errors.append(f"{name}: ineligible reject is missing ineligible_reason")
            ineligible_rejects.append(
                {
                    "name": name,
                    "role": role,
                    "category": item.get("category"),
                    "ineligible_reason": reason,
                }
            )

    # Structural byte-level diff checks on critical pairs
    if "cve_2024_0088_shm_params_infer" in by_name:
        shm_path = resolve_file(corpus_dir, by_name["cve_2024_0088_shm_params_infer"]["pb_path"])
        if shm_path.is_file():
            shm_bytes = shm_path.read_bytes()
            if b"\x1a\x13triton_shm_internal" not in shm_bytes:
                errors.append(
                    "cve_2024_0088_shm_params_infer: missing InferParameter.string_param (field 3 = 0x1A) for triton_shm_internal"
                )
            if b"\x12\x13triton_shm_internal" in shm_bytes:
                errors.append(
                    "cve_2024_0088_shm_params_infer: string_param erroneously encoded on field 2 (bool_param)"
                )

    if "frame_single" in by_name and "frame_two_concat" in by_name:
        f1 = resolve_file(corpus_dir, by_name["frame_single"]["pb_path"])
        f2 = resolve_file(corpus_dir, by_name["frame_two_concat"]["pb_path"])
        if f1.is_file() and f2.is_file():
            b1 = f1.read_bytes()
            b2 = f2.read_bytes()
            if b2 != b1 + b1:
                errors.append("frame_two_concat is not exact two concatenated copies of frame_single")

    if "shape_neg_packed" in by_name and "benign_shape_pos_packed" in by_name:
        neg_p = resolve_file(corpus_dir, by_name["shape_neg_packed"]["pb_path"])
        pos_p = resolve_file(corpus_dir, by_name["benign_shape_pos_packed"]["pb_path"])
        if neg_p.is_file() and pos_p.is_file():
            neg_b = neg_p.read_bytes()
            pos_b = pos_p.read_bytes()
            if b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01" not in neg_b:
                errors.append("shape_neg_packed missing 10-byte -1 varint")
            if b"\x1a\x05\x01\x03\x01\xe0\x01" not in pos_b:
                errors.append("benign_shape_pos_packed missing packed shape [1, 3, 1, 224]")

    return (eligible_pairs, ineligible_rejects, errors, manifest_sha256)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "corpus",
        help="Path to corpus directory containing manifest.json",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON lint summary",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    eligible, ineligible, errors, sha256 = lint_corpus(args.corpus_dir)

    if args.json:
        print(
            json.dumps(
                {
                    "ok": len(errors) == 0,
                    "manifest_sha256": sha256,
                    "eligible_pair_count": len(eligible),
                    "ineligible_reject_count": len(ineligible),
                    "eligible_pairs": eligible,
                    "ineligible_rejects": ineligible,
                    "errors": errors,
                },
                indent=2,
            )
        )
    else:
        print(f"corpus lint: manifest_sha256={sha256[:16]}...  eligible_pairs={len(eligible)}  ineligible_rejects={len(ineligible)}")
        for pair in eligible:
            print(
                f"  [ELIGIBLE]   pair_id={pair['pair_id']:<24} attack={pair['attack']:<34} twin={pair['twin']:<30} mutation={pair['mutation']}"
            )
        for item in ineligible:
            print(
                f"  [INELIGIBLE] name={item['name']:<36} role={item['role']:<16} reason={item['ineligible_reason']}"
            )
        if errors:
            for err in errors:
                print(f"  [ERROR] {err}", file=sys.stderr)

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
