"""Oracle payloads for the admission sweep.

``expected`` is the decision a KServe v2 peer should make. It is not a
prediction of the current scanner. Allow-oracle files live in
``corpus/benign/`` and reject-oracle files live in ``corpus/malicious/``.
Pre-framed HTTP bodies and header-only RPC probes live outside those
directories so ``Corpus::load`` and the 1% interleave do not send them.

The 64 MiB ceiling twin is implemented and stays off unless
``include_ceiling_blob`` is set. It is not part of the default corpus.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from exploit_generator import (
    _model_name_header,
    _packed_shape,
    cve_2024_0088_shm_params_infer,
    encode_length_delimited,
    encode_string,
    encode_tag,
    encode_varint,
)
from wire_utils import (
    MODEL_INFER_METHOD,
    Artifact,
    grpc_frame,
    write_dual,
)

SERVICE = "/inference.GRPCInferenceService"
FLOATS_1_TO_4 = (1.0, 2.0, 3.0, 4.0)
PACKED_FLOATS = struct.pack("<4f", *FLOATS_1_TO_4)
CEILING_ELEMENTS = 16_777_216
CEILING_RAW_BYTES = CEILING_ELEMENTS * 4
PACKED_ONES = 100_000


def _input(
    name: str,
    datatype: str,
    dims: list[int],
    *,
    parameters: bytes = b"",
    contents: bytes | None = None,
) -> bytes:
    parts = [
        encode_string(1, name),
        encode_string(2, datatype),
        _packed_shape(dims),
        parameters,
    ]
    if contents is not None:
        parts.append(encode_length_delimited(5, contents))
    return b"".join(parts)


def _request(
    inputs: list[bytes],
    raws: list[bytes],
    request_id: str,
    *,
    raws_first: bool = False,
) -> bytes:
    header = b"".join(
        (
            _model_name_header(),
            encode_string(2, "1"),
            encode_string(3, request_id),
        )
    )
    input_fields = b"".join(encode_length_delimited(5, item) for item in inputs)
    raw_fields = b"".join(encode_length_delimited(7, raw) for raw in raws)
    if raws_first:
        return header + raw_fields + input_fields
    return header + input_fields + raw_fields


def _fp32_packed(values: tuple[float, ...]) -> bytes:
    """InferTensorContents.fp32_contents, field 6, packed wire type 2."""
    raw = b"".join(struct.pack("<f", value) for value in values)
    return encode_length_delimited(6, raw)


def _fp32_unpacked(values: tuple[float, ...]) -> bytes:
    """InferTensorContents.fp32_contents, field 6, repeated wire type 5."""
    out = bytearray()
    for value in values:
        out.extend(encode_tag(6, 5))
        out.extend(struct.pack("<f", value))
    return bytes(out)


def _param_int(key: str, value: int) -> bytes:
    """InferInputTensor.parameters entry. InferParameter.int64_param is field 2."""
    infer_param = encode_tag(2, 0) + encode_varint(value)
    entry = encode_string(1, key) + encode_length_delimited(2, infer_param)
    return encode_length_delimited(4, entry)


def _bytes_chunk(parts: list[bytes]) -> bytes:
    return b"".join(struct.pack("<I", len(part)) + part for part in parts)


def _tiny_model_infer() -> bytes:
    """One FP32 element and a matching 4-byte raw chunk."""
    raw = struct.pack("<f", 1.0)
    return _request([_input("input0", "FP32", [1])], [raw], "frame_single")


def benign_multichunk_aligned() -> bytes:
    return _request(
        [_input("input0", "FP32", [4]), _input("input1", "FP32", [1])],
        [b"\x00" * 16, b"\x00" * 4],
        "benign_multichunk_aligned",
    )


def benign_contents_fp32_unpacked() -> bytes:
    return _request(
        [_input("input0", "FP32", [1, 4], contents=_fp32_unpacked(FLOATS_1_TO_4))],
        [],
        "benign_contents_fp32_unpacked",
    )


def benign_contents_fp32_packed() -> bytes:
    return _request(
        [_input("input0", "FP32", [1, 4], contents=_fp32_packed(FLOATS_1_TO_4))],
        [],
        "benign_contents_fp32_packed",
    )


def benign_mixed_fp32_bytes() -> bytes:
    strings = [b"alpha", b"beta"]
    return _request(
        [
            _input("image", "FP32", [1, 4]),
            _input("text", "BYTES", [1, len(strings)]),
        ],
        [PACKED_FLOATS, _bytes_chunk(strings)],
        "benign_mixed_fp32_bytes",
    )


def benign_param_binary_data_size() -> bytes:
    return _request(
        [_input("input0", "FP32", [1, 4], parameters=_param_int("binary_data_size", 16))],
        [PACKED_FLOATS],
        "benign_param_binary_data_size",
    )


def benign_shape_zero_axis() -> bytes:
    return _request(
        [_input("input0", "FP32", [1, 0, 224, 224])],
        [b""],
        "benign_shape_zero_axis",
    )


def _dtype_request(name: str, datatype: str, raw_len: int) -> bytes:
    return _request(
        [_input("input0", datatype, [1, 4])],
        [bytes((index + 1) & 0xFF for index in range(raw_len))],
        name,
    )


def benign_fp32_ceiling() -> bytes:
    """One FP32 tensor at the 16,777,216-element ceiling with a 64 MiB raw chunk.

    The default generator does not write this. Envoy's listener cap is 16 MiB,
    so the blob is a unit-test / opt-in payload only.
    """
    return _request(
        [_input("input0", "FP32", [CEILING_ELEMENTS])],
        [b"\x00" * CEILING_RAW_BYTES],
        "benign_fp32_ceiling",
    )


def chunk_swap_fp32() -> bytes:
    return _request(
        [_input("input0", "FP32", [4]), _input("input1", "FP32", [1])],
        [b"\x11" * 4, b"\x22" * 16],
        "chunk_swap_fp32",
    )


def chunk_omitted_fp32() -> bytes:
    return _request(
        [_input("input0", "FP32", [4]), _input("input1", "FP32", [1])],
        [b"\x33" * 20],
        "chunk_omitted_fp32",
    )


def chunk_swap_reordered() -> bytes:
    return _request(
        [_input("input0", "FP32", [4]), _input("input1", "FP32", [1])],
        [b"\x11" * 4, b"\x22" * 16],
        "chunk_swap_reordered",
        raws_first=True,
    )


def contents_fp32_unpacked_short() -> bytes:
    return _request(
        [_input("input0", "FP32", [4, 3, 224, 224], contents=_fp32_unpacked(FLOATS_1_TO_4))],
        [],
        "contents_fp32_unpacked_short",
    )


def contents_fp32_unpacked_ceiling() -> bytes:
    return _request(
        [_input("input0", "FP32", [CEILING_ELEMENTS], contents=_fp32_unpacked((1.0,)))],
        [],
        "contents_fp32_unpacked_ceiling",
    )


def bytes_length_prefix_oversize() -> bytes:
    """One BYTES element whose u32 length is 0xFFFFFFFF plus 4 payload bytes."""
    raw = struct.pack("<I", 0xFFFFFFFF) + b"\x44" * 4
    return _request(
        [_input("text", "BYTES", [1])],
        [raw],
        "bytes_length_prefix_oversize",
    )


def bytes_masks_short_fp32() -> bytes:
    """A 4-byte FP32 chunk plus a 16-byte BYTES chunk. The sums meet; the chunks do not."""
    return _request(
        [_input("image", "FP32", [4]), _input("text", "BYTES", [1])],
        [b"\x55" * 4, _bytes_chunk([b"\x66" * 12])],
        "bytes_masks_short_fp32",
    )


def shape_sum_four_ceilings() -> bytes:
    inputs = [_input(f"input{index}", "FP32", [CEILING_ELEMENTS]) for index in range(4)]
    return _request(inputs, [], "shape_sum_four_ceilings")


def shape_packed_ones() -> bytes:
    return _request(
        [_input("input0", "FP32", [1] * PACKED_ONES)],
        [struct.pack("<f", 1.0)],
        "shape_packed_ones",
    )


def datatype_fp64_short_raw() -> bytes:
    return _request(
        [_input("input0", "FP64", [1, 4])],
        [PACKED_FLOATS],
        "datatype_fp64_short_raw",
    )


def datatype_unknown_width() -> bytes:
    return _request(
        [_input("input0", "FP32 ", [1, 4])],
        [PACKED_FLOATS],
        "datatype_unknown_width",
    )


def _write_http_body(
    directory: Path,
    name: str,
    body: bytes,
    *,
    expected: str,
    method: str,
    notes: str,
) -> Artifact:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.body"
    path.write_bytes(body)
    repo_root = directory.parent.parent
    try:
        rel = path.relative_to(repo_root).as_posix()
    except ValueError:
        rel = path.as_posix()
    return Artifact(
        name=name,
        category="framing",
        expected=expected,
        pb_path=rel,
        grpc_path=rel,
        pb_bytes=len(body),
        grpc_bytes=len(body),
        notes=notes,
        method=method,
        framing="http-body",
    )


def _rpc_row(base: Artifact, name: str, method: str, expected: str, notes: str) -> Artifact:
    return Artifact(
        name=name,
        category="rpc",
        expected=expected,
        pb_path=base.pb_path,
        grpc_path=base.grpc_path,
        pb_bytes=base.pb_bytes,
        grpc_bytes=base.grpc_bytes,
        notes=notes,
        method=method,
        framing="protobuf",
    )


def generate_oracle(corpus_root: Path, *, include_ceiling_blob: bool = False) -> list[Artifact]:
    """Write oracle payloads and return their manifest entries."""
    benign = corpus_root / "benign"
    malicious = corpus_root / "malicious"
    artifacts: list[Artifact] = []

    allow_rows: list[tuple[str, bytes, str, str]] = [
        (
            "benign_multichunk_aligned",
            benign_multichunk_aligned(),
            "chunk_parity",
            "FP32 [4] then FP32 [1] with raw chunks of 16 then 4 bytes",
        ),
        (
            "benign_contents_fp32_unpacked",
            benign_contents_fp32_unpacked(),
            "tensor_contents",
            "FP32 [1,4] as four unpacked fp32_contents (field 6, wire type 5), no raw_input_contents",
        ),
        (
            "benign_contents_fp32_packed",
            benign_contents_fp32_packed(),
            "tensor_contents",
            "FP32 [1,4] as packed fp32_contents (field 6, wire type 2) holding float32 1,2,3,4, no raw_input_contents",
        ),
        (
            "benign_mixed_fp32_bytes",
            benign_mixed_fp32_bytes(),
            "bytes_prefix",
            "FP32 [1,4] raw of 16 bytes plus BYTES [1,2] with little-endian u32 prefixes",
        ),
        (
            "benign_param_binary_data_size",
            benign_param_binary_data_size(),
            "parameters",
            "FP32 [1,4] with InferParameter key binary_data_size on int64_param field 2",
        ),
        (
            "benign_shape_zero_axis",
            benign_shape_zero_axis(),
            "shape_axis",
            "FP32 [1,0,224,224] with an empty raw_input_contents. KServe allows a zero axis",
        ),
        (
            "benign_dtype_bool",
            _dtype_request("benign_dtype_bool", "BOOL", 4),
            "datatype",
            "BOOL [1,4] with a 4-byte raw chunk",
        ),
        (
            "benign_dtype_fp16",
            _dtype_request("benign_dtype_fp16", "FP16", 8),
            "datatype",
            "FP16 [1,4] with an 8-byte raw chunk",
        ),
        (
            "benign_dtype_bf16",
            _dtype_request("benign_dtype_bf16", "BF16", 8),
            "datatype",
            "BF16 [1,4] with an 8-byte raw chunk",
        ),
        (
            "benign_dtype_fp64",
            _dtype_request("benign_dtype_fp64", "FP64", 32),
            "datatype",
            "FP64 [1,4] with a 32-byte raw chunk",
        ),
    ]
    for name, payload, category, notes in allow_rows:
        artifacts.append(
            write_dual(
                benign,
                name,
                payload,
                category=category,
                expected="allow",
                notes=notes,
            )
        )

    if include_ceiling_blob:
        artifacts.append(
            write_dual(
                benign,
                "benign_fp32_ceiling",
                benign_fp32_ceiling(),
                category="shape_budget",
                expected="allow",
                notes=(
                    f"FP32 [{CEILING_ELEMENTS}] with a {CEILING_RAW_BYTES}-byte raw chunk. "
                    "Opt-in only; the Envoy listener cap is 16 MiB"
                ),
            )
        )

    reject_rows: list[tuple[str, bytes, str, str]] = [
        (
            "chunk_swap_fp32",
            chunk_swap_fp32(),
            "chunk_parity",
            "FP32 [4] bound to a 4-byte chunk and FP32 [1] bound to a 16-byte chunk",
        ),
        (
            "chunk_omitted_fp32",
            chunk_omitted_fp32(),
            "chunk_parity",
            "Two tensors expecting 16 and 4 bytes, with a single 20-byte raw chunk",
        ),
        (
            "chunk_swap_reordered",
            chunk_swap_reordered(),
            "chunk_parity",
            "Swapped raw chunks written before the inputs. Binding is by index, not wire order",
        ),
        (
            "contents_fp32_unpacked_short",
            contents_fp32_unpacked_short(),
            "tensor_contents",
            "FP32 [4,3,224,224] with four unpacked fp32 values and no raw_input_contents",
        ),
        (
            "contents_fp32_unpacked_ceiling",
            contents_fp32_unpacked_ceiling(),
            "tensor_contents",
            "FP32 [16777216] with one unpacked fp32 value and no raw_input_contents",
        ),
        (
            "bytes_length_prefix_oversize",
            bytes_length_prefix_oversize(),
            "bytes_prefix",
            "BYTES [1] whose little-endian u32 length is 0xFFFFFFFF inside an 8-byte chunk",
        ),
        (
            "bytes_masks_short_fp32",
            bytes_masks_short_fp32(),
            "bytes_prefix",
            "FP32 [4] chunk of 4 bytes compensated by a 16-byte BYTES chunk",
        ),
        (
            "shape_sum_four_ceilings",
            shape_sum_four_ceilings(),
            "shape_budget",
            "Four FP32 [16777216] tensors and no raw chunks. Declared elements are 4 times the per-tensor ceiling",
        ),
        (
            "shape_packed_ones",
            shape_packed_ones(),
            "shape_budget",
            "One packed shape of 100000 dimensions of 1 (product stays 1). latency_ns is the measurement against the 250 ms ext_proc deadline",
        ),
        (
            "datatype_fp64_short_raw",
            datatype_fp64_short_raw(),
            "datatype",
            "FP64 [1,4] with a 16-byte raw chunk (the FP32 length)",
        ),
        (
            "datatype_unknown_width",
            datatype_unknown_width(),
            "datatype",
            "Datatype 'FP32 ' (trailing space) on shape [1,4] with a 16-byte raw chunk. Unknown width fails closed",
        ),
    ]
    for name, payload, category, notes in reject_rows:
        artifacts.append(
            write_dual(
                malicious,
                name,
                payload,
                category=category,
                expected="reject",
                notes=notes,
            )
        )

    framing_dir = corpus_root / "framing"
    inner = _tiny_model_infer()
    one = grpc_frame(inner)
    two = one + one
    artifacts.append(
        _write_http_body(
            framing_dir,
            "frame_single",
            one,
            expected="allow",
            method=MODEL_INFER_METHOD,
            notes="One uncompressed gRPC frame whose declared length equals the body. Sent as the HTTP body, not via tonic",
        )
    )
    artifacts.append(
        _write_http_body(
            framing_dir,
            "frame_two_concat",
            two,
            expected="reject",
            method=MODEL_INFER_METHOD,
            notes="Two complete frames concatenated in one HTTP body",
        )
    )
    artifacts.append(
        _write_http_body(
            framing_dir,
            "frame_stream_infer_two",
            two,
            expected="reject",
            method=f"{SERVICE}/ModelStreamInfer",
            notes="ModelStreamInfer is not on the RPC allowlist. The body is also two frames",
        )
    )

    rpc_dir = corpus_root / "rpc"
    empty = write_dual(
        rpc_dir,
        "empty_model_infer",
        b"",
        category="rpc",
        expected="allow",
        notes="Shared empty protobuf. Tonic adds the 5-byte frame. Not loaded by Corpus::load",
    )
    rpc_rows = [
        (
            "rpc_model_infer_empty",
            f"{SERVICE}/ModelInfer",
            "allow",
            "Empty ModelInfer message. The framed body is a zero-length protobuf",
        ),
        (
            "rpc_system_shared_memory_register",
            f"{SERVICE}/SystemSharedMemoryRegister",
            "reject",
            "Header allowlist probe. Expected block is PERMISSION_DENIED or HTTP 403, and the body is not forwarded",
        ),
        (
            "rpc_cuda_shared_memory_register",
            f"{SERVICE}/CudaSharedMemoryRegister",
            "reject",
            "Header allowlist probe. Expected block is PERMISSION_DENIED or HTTP 403",
        ),
        (
            "rpc_repository_model_load",
            f"{SERVICE}/RepositoryModelLoad",
            "reject",
            "Header allowlist probe. Expected block is PERMISSION_DENIED or HTTP 403",
        ),
        (
            "rpc_repository_model_unload",
            f"{SERVICE}/RepositoryModelUnload",
            "reject",
            "Header allowlist probe. Expected block is PERMISSION_DENIED or HTTP 403",
        ),
    ]
    for name, method, expected, notes in rpc_rows:
        artifacts.append(_rpc_row(empty, name, method, expected, notes))
    return artifacts


def _read_varint(blob: bytes, index: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while index < len(blob):
        byte = blob[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, index
        shift += 7
        if shift > 63:
            raise ValueError("varint overflow")
    raise ValueError("truncated varint")


def root_length_fields(blob: bytes) -> list[tuple[int, bytes]]:
    """Return root length-delimited fields as ``(field_number, payload)``."""
    found: list[tuple[int, bytes]] = []
    index = 0
    while index < len(blob):
        key, index = _read_varint(blob, index)
        field, wire = key >> 3, key & 7
        if wire == 0:
            _, index = _read_varint(blob, index)
        elif wire == 1:
            index += 8
        elif wire == 2:
            length, index = _read_varint(blob, index)
            found.append((field, blob[index : index + length]))
            index += length
        elif wire == 5:
            index += 4
        else:
            raise ValueError(f"unsupported wire type {wire}")
    return found


def validate_corpus(corpus: Path, *, ceiling: bool) -> None:
    """Check the generated manifest and the oracle byte patterns."""
    manifest_path = corpus / "manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if payload.get("schema") != "custos-benchmarks.corpus.v2":
        raise RuntimeError(f"unexpected manifest schema: {payload.get('schema')}")
    artifacts = payload["artifacts"]
    if payload["count"] != len(artifacts):
        raise RuntimeError("manifest count does not match artifacts")
    names = [item["name"] for item in artifacts]
    if len(names) != len(set(names)):
        raise RuntimeError("manifest contains a duplicate name")

    required_allow = [
        "benign_b1",
        "benign_bytes_tensor",
        "benign_multichunk_aligned",
        "benign_contents_fp32_unpacked",
        "benign_contents_fp32_packed",
        "benign_mixed_fp32_bytes",
        "benign_param_binary_data_size",
        "benign_shape_zero_axis",
        "benign_dtype_bool",
        "benign_dtype_fp16",
        "benign_dtype_bf16",
        "benign_dtype_fp64",
    ]
    required_reject = [
        "chunk_swap_fp32",
        "chunk_omitted_fp32",
        "chunk_swap_reordered",
        "contents_fp32_unpacked_short",
        "contents_fp32_unpacked_ceiling",
        "bytes_length_prefix_oversize",
        "bytes_masks_short_fp32",
        "shape_sum_four_ceilings",
        "shape_packed_ones",
        "datatype_fp64_short_raw",
        "datatype_unknown_width",
        "frame_two_concat",
        "frame_stream_infer_two",
        "rpc_system_shared_memory_register",
        "rpc_cuda_shared_memory_register",
        "rpc_repository_model_load",
        "rpc_repository_model_unload",
    ]
    by_name = {item["name"]: item for item in artifacts}
    for name in required_allow:
        if by_name[name]["expected"] != "allow":
            raise RuntimeError(f"{name} expected allow")
    for name in required_reject:
        if by_name[name]["expected"] != "reject":
            raise RuntimeError(f"{name} expected reject")
    if ("benign_fp32_ceiling" in by_name) != ceiling:
        raise RuntimeError("ceiling blob flag does not match the manifest")

    def load(name: str) -> bytes:
        rel = Path(by_name[name]["pb_path"])
        path = (corpus.parent / rel) if not rel.is_absolute() else rel
        return path.read_bytes()

    aligned = root_length_fields(load("benign_multichunk_aligned"))
    aligned_raws = [len(body) for field, body in aligned if field == 7]
    if aligned_raws != [16, 4]:
        raise RuntimeError(f"aligned chunks are {aligned_raws}")
    if [field for field, _ in aligned].index(5) > [field for field, _ in aligned].index(7):
        raise RuntimeError("aligned payload writes raw chunks before inputs")

    swapped = root_length_fields(load("chunk_swap_fp32"))
    if [len(body) for field, body in swapped if field == 7] != [4, 16]:
        raise RuntimeError("chunk_swap_fp32 chunk lengths")
    omitted = root_length_fields(load("chunk_omitted_fp32"))
    if [len(body) for field, body in omitted if field == 7] != [20]:
        raise RuntimeError("chunk_omitted_fp32 should have one 20-byte chunk")
    reordered = root_length_fields(load("chunk_swap_reordered"))
    reordered_fields = [field for field, _ in reordered]
    if reordered_fields.index(7) > reordered_fields.index(5):
        raise RuntimeError("chunk_swap_reordered should write field 7 first")

    packed = load("benign_contents_fp32_packed")
    if _fp32_packed(FLOATS_1_TO_4) not in packed:
        raise RuntimeError("packed fp32 contents missing float32 1,2,3,4")
    if PACKED_FLOATS != bytes.fromhex("0000803f000000400000404000008040"):
        raise RuntimeError("float32 1..4 byte pattern changed")
    unpacked = load("benign_contents_fp32_unpacked")
    if unpacked.count(bytes([encode_tag(6, 5)[0]])) < 4:
        raise RuntimeError("unpacked fp32 contents should carry four wire-type-5 values")
    short = root_length_fields(load("contents_fp32_unpacked_short"))
    if any(field == 7 for field, _ in short):
        raise RuntimeError("contents short twin should have no field 7")

    zero = load("benign_shape_zero_axis")
    if _packed_shape([1, 0, 224, 224]) not in zero:
        raise RuntimeError("zero-axis shape missing")

    shm = cve_2024_0088_shm_params_infer()
    if shm != load("cve_2024_0088_shm_params_infer"):
        raise RuntimeError("shm payload on disk does not match the generator")
    if encode_string(3, "triton_shm_internal") not in shm:
        raise RuntimeError("shm region must be InferParameter.string_param field 3")
    if encode_string(2, "triton_shm_internal") in shm:
        raise RuntimeError("shm region is encoded on field 2")
    if encode_tag(2, 0) + encode_varint(0x7FFFFFFF) not in shm:
        raise RuntimeError("shm offset must be InferParameter.int64_param field 2")

    single = load("frame_single")
    if single[:1] != b"\x00":
        raise RuntimeError("frame_single does not start with the uncompressed flag")
    declared = int.from_bytes(single[1:5], "big")
    if declared != len(single) - 5:
        raise RuntimeError("frame_single length does not match the body")
    two = load("frame_two_concat")
    if two != single + single:
        raise RuntimeError("frame_two_concat is not two copies of frame_single")
    if int.from_bytes(two[1:5], "big") == len(two) - 5:
        raise RuntimeError("frame_two_concat unexpectedly satisfies the single-frame length check")
    if load("frame_stream_infer_two") != two:
        raise RuntimeError("stream-infer body should match the two-frame body")
    if by_name["frame_stream_infer_two"]["method"] != f"{SERVICE}/ModelStreamInfer":
        raise RuntimeError("stream-infer method path")
    if by_name["frame_single"]["framing"] != "http-body":
        raise RuntimeError("framing artifacts must be http-body")
    for name in ("frame_single", "frame_two_concat", "frame_stream_infer_two"):
        rel = by_name[name]["pb_path"]
        if "/benign/" in rel or "/malicious/" in rel:
            raise RuntimeError(f"{name} must stay out of the tonic corpus directories")
    for name in (
        "rpc_model_infer_empty",
        "rpc_system_shared_memory_register",
        "rpc_cuda_shared_memory_register",
        "rpc_repository_model_load",
        "rpc_repository_model_unload",
    ):
        item = by_name[name]
        if item["framing"] != "protobuf":
            raise RuntimeError(f"{name} should be sent as protobuf")
        if "/benign/" in item["pb_path"] or "/malicious/" in item["pb_path"]:
            raise RuntimeError(f"{name} must stay out of the tonic corpus directories")
        if item["method"] != f"{SERVICE}/{_rpc_leaf(name)}":
            raise RuntimeError(f"{name} method is {item['method']}")
    if load("rpc_model_infer_empty") != b"":
        raise RuntimeError("rpc body should be an empty protobuf")

    ones = load("shape_packed_ones")
    if _packed_shape([1] * PACKED_ONES) not in ones:
        raise RuntimeError("packed ones shape missing")
    ceilings = root_length_fields(load("shape_sum_four_ceilings"))
    if sum(1 for field, _ in ceilings if field == 5) != 4:
        raise RuntimeError("four ceiling tensors were not written")
    if any(field == 7 for field, _ in ceilings):
        raise RuntimeError("ceiling sum should have no field 7")


def _rpc_leaf(name: str) -> str:
    return {
        "rpc_model_infer_empty": "ModelInfer",
        "rpc_system_shared_memory_register": "SystemSharedMemoryRegister",
        "rpc_cuda_shared_memory_register": "CudaSharedMemoryRegister",
        "rpc_repository_model_load": "RepositoryModelLoad",
        "rpc_repository_model_unload": "RepositoryModelUnload",
    }[name]


def self_check() -> None:
    """Builder checks that do not rewrite the repo corpus."""
    if PACKED_FLOATS != bytes.fromhex("0000803f000000400000404000008040"):
        raise RuntimeError("packed floats are not little-endian float32 1,2,3,4")
    if CEILING_RAW_BYTES != 64 * 1024 * 1024:
        raise RuntimeError("ceiling raw size is not 64 MiB")
    import tempfile

    from wire_utils import write_manifest

    with tempfile.TemporaryDirectory() as tmp:
        corpus = Path(tmp) / "corpus"
        rows = generate_oracle(corpus, include_ceiling_blob=False)
        if any(row.name == "benign_fp32_ceiling" for row in rows):
            raise RuntimeError("default generate wrote the ceiling blob")
        if (corpus / "benign" / "benign_fp32_ceiling.pb").exists():
            raise RuntimeError("ceiling file exists without the flag")
        extras = [
            write_dual(
                corpus / "benign",
                "benign_b1",
                b"\x0a",
                category="benign",
                expected="allow",
                notes="placeholder",
            ),
            write_dual(
                corpus / "benign",
                "benign_bytes_tensor",
                b"\x0a",
                category="benign",
                expected="allow",
                notes="placeholder",
            ),
            write_dual(
                corpus / "malicious",
                "cve_2024_0088_shm_params_infer",
                cve_2024_0088_shm_params_infer(),
                category="shm_param_injection",
                expected="reject",
                notes="placeholder",
            ),
        ]
        write_manifest(corpus / "manifest.json", extras + rows)
        validate_corpus(corpus, ceiling=False)


if __name__ == "__main__":
    self_check()
    print("oracle self-check ok")
