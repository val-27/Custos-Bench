"""Dual-artifact serialization for gRPC wire payloads.

Standard gRPC clients prepend a 5-byte frame header
``[compression_flag:u8, message_length:u32be]`` before the protobuf
message. ``custos-bench`` consumes raw ``.pb`` bytes and lets tonic
add that header, so writing a framed payload into ``.pb`` would
double-frame the request. Offline unit tests that do not go through a
gRPC stack consume the pre-framed ``.grpc`` sibling instead.
"""

from __future__ import annotations

import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

GRPC_COMPRESSION_NONE = 0x00
GRPC_HEADER_STRUCT = struct.Struct(">BI")


@dataclass(frozen=True)
class Artifact:
    """Index entry for one generated payload."""

    name: str
    category: str
    expected: str
    pb_path: str
    grpc_path: str
    pb_bytes: int
    grpc_bytes: int
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def grpc_frame(pb_bytes: bytes) -> bytes:
    """Prepend the uncompressed gRPC length-prefixed frame header."""
    if len(pb_bytes) > 0xFFFFFFFF:
        raise ValueError(f"payload {len(pb_bytes)} exceeds u32 gRPC length")
    return GRPC_HEADER_STRUCT.pack(GRPC_COMPRESSION_NONE, len(pb_bytes)) + pb_bytes


def write_dual(
    directory: Path,
    name: str,
    pb_bytes: bytes,
    *,
    category: str,
    expected: str,
    notes: str = "",
) -> Artifact:
    """Write ``<name>.pb`` and ``<name>.grpc`` and return the manifest entry."""
    directory.mkdir(parents=True, exist_ok=True)
    pb_path = directory / f"{name}.pb"
    grpc_path = directory / f"{name}.grpc"
    framed = grpc_frame(pb_bytes)
    pb_path.write_bytes(pb_bytes)
    grpc_path.write_bytes(framed)
    return Artifact(
        name=name,
        category=category,
        expected=expected,
        pb_path=str(pb_path.as_posix()),
        grpc_path=str(grpc_path.as_posix()),
        pb_bytes=len(pb_bytes),
        grpc_bytes=len(framed),
        notes=notes,
    )


def write_manifest(path: Path, artifacts: Iterable[Artifact]) -> None:
    """Write ``corpus/manifest.json`` indexing every generated payload."""
    entries = [artifact.to_dict() for artifact in artifacts]
    payload = {
        "schema": "custos-benchmarks.corpus.v1",
        "count": len(entries),
        "artifacts": entries,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
