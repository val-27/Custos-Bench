"""Wire-level malformed Protobuf payloads for Custos admission tests.

Encoders operate on the protobuf wire format directly so that illegal
varints, illegal nesting, and illegal tensor shapes can be emitted
without a generated stub refusing to serialize them.
"""

from __future__ import annotations

from pathlib import Path

from wire_utils import Artifact, write_dual

MODEL_NAME = b"resnet50"
NESTING_DEPTHS = (15, 16, 17, 20, 50, 100, 250, 500)
# KServe v2 ModelInferRequest.inputs is field 5, wire type 2 -> tag 0x2A.
INPUTS_TAG = b"\x2a"
# InferInputTensor.shape packed (field 3, wire type 2) and unpacked (field 3, wire type 0).
SHAPE_PACKED_TAG = 0x1A
SHAPE_UNPACKED_TAG = 0x18
LEAF = b"\x08\x01"
NEG_ONE_VARINT = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"


def encode_varint(value: int) -> bytes:
    """Encode an unsigned integer as a protobuf base-128 varint."""
    if value < 0:
        raise ValueError("encode_varint expects a non-negative integer; mask signed values first")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def encode_tag(field_number: int, wire_type: int) -> bytes:
    """Encode a protobuf key (field_number << 3 | wire_type)."""
    if field_number < 1:
        raise ValueError("field_number must be >= 1")
    if wire_type not in (0, 1, 2, 5):
        raise ValueError(f"unsupported wire type {wire_type}")
    return encode_varint((field_number << 3) | wire_type)


def encode_length_delimited(field_number: int, payload: bytes) -> bytes:
    """Encode a length-delimited field (wire type 2)."""
    return encode_tag(field_number, 2) + encode_varint(len(payload)) + payload


def encode_string(field_number: int, value: str) -> bytes:
    return encode_length_delimited(field_number, value.encode("utf-8"))


def _model_name_header() -> bytes:
    return encode_length_delimited(1, MODEL_NAME)


def _zigzag_varint(value: int) -> bytes:
    """Two's-complement protobuf int64 varint (not zigzag). Negative values wrap mod 2**64."""
    return encode_varint(value & 0xFFFFFFFFFFFFFFFF)


def nesting_bomb(depth: int) -> bytes:
    """Wrap ``depth`` field-5 length-delimited frames around a leaf varint.

    The outermost frame is a real ``ModelInferRequest.inputs`` tag so a
    recursive descent parser that walks submessages of field 5 hits the
    configured depth limit. Depths 15 and 16 sit on the acceptance
    boundary; depths >= 17 are expected to be rejected.
    """
    if depth < 1:
        raise ValueError("depth must be >= 1")
    body = LEAF
    for _ in range(depth):
        body = INPUTS_TAG + encode_varint(len(body)) + body
    return _model_name_header() + body


def _packed_shape(dimensions: list[int]) -> bytes:
    packed = b"".join(_zigzag_varint(dim) for dim in dimensions)
    return bytes([SHAPE_PACKED_TAG]) + encode_varint(len(packed)) + packed


def _unpacked_shape(dimensions: list[int]) -> bytes:
    chunks = []
    for dim in dimensions:
        chunks.append(bytes([SHAPE_UNPACKED_TAG]) + _zigzag_varint(dim))
    return b"".join(chunks)


def _infer_input(shape_bytes: bytes, *, name: str = "input_tensor", datatype: str = "FP32") -> bytes:
    return b"".join(
        (
            encode_string(1, name),
            encode_string(2, datatype),
            shape_bytes,
        )
    )


def _request_with_input(shape_bytes: bytes, *, raw_input: bytes | None = None, raw_first: bool = False) -> bytes:
    infer_input = _infer_input(shape_bytes)
    input_field = encode_length_delimited(5, infer_input)
    parts = [_model_name_header(), encode_string(2, "1"), encode_string(3, "exploit")]
    raw_field = encode_length_delimited(7, raw_input) if raw_input is not None else b""
    if raw_first:
        parts.extend((raw_field, input_field))
    else:
        parts.extend((input_field, raw_field))
    return b"".join(parts)


def shape_neg_packed() -> bytes:
    return _request_with_input(_packed_shape([1, 3, -1, 224]))


def shape_neg_unpacked() -> bytes:
    return _request_with_input(_unpacked_shape([1, 3, -1, 224]))


def shape_wrap_64bit_packed() -> bytes:
    # 2 * 2**62 * 2 = 2**64 ≡ 0 (mod 2**64)
    return _request_with_input(_packed_shape([2, 4611686018427387904, 2]))


def shape_wrap_64bit_unpacked() -> bytes:
    return _request_with_input(_unpacked_shape([2, 4611686018427387904, 2]))


def shape_oom_massive_packed() -> bytes:
    return _request_with_input(_packed_shape([1024, 1024, 1024]))


def shape_oom_massive_unpacked() -> bytes:
    return _request_with_input(_unpacked_shape([1024, 1024, 1024]))


def shape_reordered_tail() -> bytes:
    """16 KiB raw_input_contents (field 7) precedes the malicious field 5.

    A checker that decides admission from a prefix of the buffer, before
    the tensor metadata arrives, would miss the overflowing shape.
    """
    return _request_with_input(
        _packed_shape([1024, 1024, 1024]),
        raw_input=b"\x00" * (16 * 1024),
        raw_first=True,
    )


def varint_unterminated_11() -> bytes:
    return _model_name_header() + b"\x08" + (b"\xff" * 11)


def varint_unterminated_64() -> bytes:
    return _model_name_header() + b"\x08" + (b"\x80" * 64)


def varint_10th_byte_overflow() -> bytes:
    # 9 continuation bytes then a terminating byte whose low bits do not fit in 64.
    return _model_name_header() + b"\x08" + (b"\xff" * 9) + b"\x7f"


def varint_truncated_eof() -> bytes:
    return _model_name_header() + b"\x08" + (b"\xff" * 3)


def generate_exploits(corpus_root: Path) -> list[Artifact]:
    """Write every exploit family into ``corpus/malicious``."""
    out_dir = corpus_root / "malicious"
    artifacts: list[Artifact] = []

    for depth in NESTING_DEPTHS:
        expected = "allow" if depth <= 16 else "reject"
        artifacts.append(
            write_dual(
                out_dir,
                f"nesting_depth_{depth}",
                nesting_bomb(depth),
                category="nesting_bomb",
                expected=expected,
                notes=f"field-5 length-delimited wrap depth={depth}; boundary allow is D<=16",
            )
        )

    shape_payloads: list[tuple[str, bytes, str]] = [
        (
            "shape_neg_packed",
            shape_neg_packed(),
            "packed shape [1,3,-1,224]; -1 is the 10-byte two's-complement varint",
        ),
        (
            "shape_neg_unpacked",
            shape_neg_unpacked(),
            "unpacked shape [1,3,-1,224] via repeated tag 0x18",
        ),
        (
            "shape_wrap_64bit_packed",
            shape_wrap_64bit_packed(),
            "packed shape [2, 2**62, 2] whose product is 0 mod 2**64",
        ),
        (
            "shape_wrap_64bit_unpacked",
            shape_wrap_64bit_unpacked(),
            "unpacked shape [2, 2**62, 2]",
        ),
        (
            "shape_oom_massive_packed",
            shape_oom_massive_packed(),
            "packed shape [1024,1024,1024] ~= 1.07e9 elements",
        ),
        (
            "shape_oom_massive_unpacked",
            shape_oom_massive_unpacked(),
            "unpacked shape [1024,1024,1024]",
        ),
        (
            "shape_reordered_tail",
            shape_reordered_tail(),
            "16 KiB field 7 precedes malicious field 5 [1024,1024,1024]",
        ),
    ]
    for name, payload, notes in shape_payloads:
        artifacts.append(
            write_dual(
                out_dir,
                name,
                payload,
                category="shape_overflow",
                expected="reject",
                notes=notes,
            )
        )

    varint_payloads: list[tuple[str, bytes, str]] = [
        (
            "varint_unterminated_11",
            varint_unterminated_11(),
            "tag 0x08 followed by 11 bytes of 0xFF (MSB=1)",
        ),
        (
            "varint_unterminated_64",
            varint_unterminated_64(),
            "tag 0x08 followed by 64 bytes of 0x80 (MSB=1)",
        ),
        (
            "varint_10th_byte_overflow",
            varint_10th_byte_overflow(),
            "tag 0x08, 9x 0xFF, terminating 0x7F with bits above a 64-bit shift",
        ),
        (
            "varint_truncated_eof",
            varint_truncated_eof(),
            "tag 0x08 followed by 3 bytes of 0xFF and immediate EOF",
        ),
    ]
    for name, payload, notes in varint_payloads:
        artifacts.append(
            write_dual(
                out_dir,
                name,
                payload,
                category="malformed_varint",
                expected="reject",
                notes=notes,
            )
        )
    return artifacts
