"""Generate the full benign and adversarial corpus."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from benign_generator import BATCH_SIZES, generate_benign
from exploit_generator import generate_exploits
from wire_utils import write_manifest


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=repo_root() / "corpus",
        help="directory that receives benign/, malicious/, and manifest.json",
    )
    parser.add_argument(
        "--imagenet-dir",
        type=Path,
        default=None,
        help="optional ImageNet validation directory; synthetic tensors are used if omitted",
    )
    parser.add_argument(
        "--batch-sizes",
        type=int,
        nargs="+",
        default=list(BATCH_SIZES),
        help="benign batch sizes to emit (default: 1 2 4 8 16)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    corpus_dir = args.corpus_dir
    if not corpus_dir.is_absolute():
        corpus_dir = (Path.cwd() / corpus_dir).resolve()
    imagenet_dir = args.imagenet_dir
    if imagenet_dir is not None and not imagenet_dir.is_dir():
        print(f"imagenet dir not found: {imagenet_dir}", file=sys.stderr)
        return 2

    benign = generate_benign(
        corpus_dir,
        imagenet_dir=imagenet_dir,
        batch_sizes=tuple(args.batch_sizes),
    )
    malicious = generate_exploits(corpus_dir)
    artifacts = benign + malicious
    manifest_path = corpus_dir / "manifest.json"
    write_manifest(manifest_path, artifacts)

    print(f"wrote {len(artifacts)} payloads to {corpus_dir}")
    for artifact in artifacts:
        print(
            f"  {artifact.category:18} {artifact.expected:6} "
            f"{artifact.pb_bytes:10d} B  {artifact.name}"
        )
    print(f"manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
