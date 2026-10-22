"""Deterministic KServe v2 ModelInferRequest generator for ResNet-50.

Produces a valid ``inference.ModelInferRequest`` for an ONNX Runtime
``resnet50`` model. Real ImageNet images are accepted when
``--imagenet-dir`` is supplied; otherwise a seeded synthetic tensor is
used so the generator runs without an external dataset.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from wire_utils import Artifact, write_dual

BATCH_SIZES = (1, 2, 4, 8, 16)
CHANNELS = 3
HEIGHT = 224
WIDTH = 224
RESIZE_EDGE = 256
IMAGENET_MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32)
IMAGENET_STD = np.array([0.229, 0.224, 0.225], dtype=np.float32)
SYNTHETIC_SEED = 42
MODEL_NAME = "resnet50"
MODEL_VERSION = "1"
INPUT_NAME = "input_tensor"
DATATYPE = "FP32"

_IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff"}


def tensor_nbytes(batch_size: int) -> int:
    return batch_size * CHANNELS * HEIGHT * WIDTH * 4


def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint value must be non-negative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _encode_key(field_number: int, wire_type: int) -> bytes:
    return _encode_varint((field_number << 3) | wire_type)


def _encode_bytes_field(field_number: int, payload: bytes) -> bytes:
    return _encode_key(field_number, 2) + _encode_varint(len(payload)) + payload


def _encode_string_field(field_number: int, value: str) -> bytes:
    return _encode_bytes_field(field_number, value.encode("utf-8"))


def _encode_packed_int64(values: list[int]) -> bytes:
    body = bytearray()
    for value in values:
        body.extend(_encode_varint(value & 0xFFFFFFFFFFFFFFFF))
    return bytes(body)


def encode_infer_input_tensor(
    name: str,
    datatype: str,
    shape: list[int],
) -> bytes:
    """Serialize ``InferInputTensor`` (name=1, datatype=2, shape=3 packed)."""
    return b"".join(
        (
            _encode_string_field(1, name),
            _encode_string_field(2, datatype),
            _encode_bytes_field(3, _encode_packed_int64(shape)),
        )
    )


def encode_model_infer_request(
    model_name: str,
    model_version: str,
    request_id: str,
    tensor: bytes,
    batch_size: int,
) -> bytes:
    """Serialize a KServe v2 ``ModelInferRequest``.

    Field numbers follow ``kserve_v2.proto`` / Triton ``grpc_service.proto``:
    model_name=1, model_version=2, id=3, inputs=5, raw_input_contents=7.
    """
    infer_input = encode_infer_input_tensor(
        INPUT_NAME,
        DATATYPE,
        [batch_size, CHANNELS, HEIGHT, WIDTH],
    )
    return b"".join(
        (
            _encode_string_field(1, model_name),
            _encode_string_field(2, model_version),
            _encode_string_field(3, request_id),
            _encode_bytes_field(5, infer_input),
            _encode_bytes_field(7, tensor),
        )
    )


def _center_crop(image: np.ndarray, size: int) -> np.ndarray:
    height, width = image.shape[:2]
    top = max((height - size) // 2, 0)
    left = max((width - size) // 2, 0)
    return image[top : top + size, left : left + size]


def _resize_shorter_edge(image: np.ndarray, edge: int) -> np.ndarray:
    """Resize so the shorter edge equals ``edge``, preserving aspect ratio.

    Uses a box filter implemented in NumPy so Pillow is optional. When
    Pillow is installed it is preferred for higher-quality resampling.
    """
    height, width = image.shape[:2]
    if height <= 0 or width <= 0:
        raise ValueError("image has a zero dimension")
    if min(height, width) == edge:
        return image
    scale = edge / float(min(height, width))
    new_h = max(int(round(height * scale)), edge)
    new_w = max(int(round(width * scale)), edge)
    try:
        from PIL import Image

        resized = Image.fromarray(image).resize((new_w, new_h), Image.BILINEAR)
        return np.asarray(resized, dtype=np.uint8)
    except ImportError:
        y_idx = np.linspace(0, height - 1, new_h).astype(np.int64)
        x_idx = np.linspace(0, width - 1, new_w).astype(np.int64)
        return image[y_idx][:, x_idx]


def preprocess_image(image: np.ndarray) -> np.ndarray:
    """ResNet-50 preprocessing: resize 256, center-crop 224, normalize, CHW.

    ``image`` is HWC uint8 RGB. Returns a float32 CHW tensor.
    """
    if image.ndim == 2:
        image = np.stack([image, image, image], axis=-1)
    if image.shape[-1] == 4:
        image = image[..., :3]
    if image.dtype != np.uint8:
        image = np.clip(image, 0, 255).astype(np.uint8)
    resized = _resize_shorter_edge(image, RESIZE_EDGE)
    cropped = _center_crop(resized, HEIGHT)
    if cropped.shape[0] != HEIGHT or cropped.shape[1] != WIDTH:
        cropped = cropped[:HEIGHT, :WIDTH]
        pad_h = HEIGHT - cropped.shape[0]
        pad_w = WIDTH - cropped.shape[1]
        if pad_h or pad_w:
            cropped = np.pad(cropped, ((0, pad_h), (0, pad_w), (0, 0)))
    normalized = cropped.astype(np.float32) / 255.0
    normalized = (normalized - IMAGENET_MEAN) / IMAGENET_STD
    return np.transpose(normalized, (2, 0, 1))


def _list_images(imagenet_dir: Path) -> list[Path]:
    files = [
        path
        for path in sorted(imagenet_dir.rglob("*"))
        if path.is_file() and path.suffix.lower() in _IMAGE_SUFFIXES
    ]
    return files


def _load_image(path: Path) -> np.ndarray:
    try:
        from PIL import Image

        with Image.open(path) as handle:
            return np.asarray(handle.convert("RGB"), dtype=np.uint8)
    except ImportError:
        raw = np.fromfile(path, dtype=np.uint8)
        if raw.size < HEIGHT * WIDTH * CHANNELS:
            raise ValueError(f"{path} is not a decodable image and Pillow is unavailable")
        side = int(np.sqrt(raw.size / CHANNELS))
        usable = side * side * CHANNELS
        return raw[:usable].reshape(side, side, CHANNELS)


def _synthetic_batch(batch_size: int, rng: np.random.Generator) -> np.ndarray:
    """Deterministic NCHW float32 tensor in the normalized ResNet range."""
    return rng.standard_normal(
        (batch_size, CHANNELS, HEIGHT, WIDTH),
        dtype=np.float32,
    )


def build_batch(
    batch_size: int,
    *,
    imagenet_dir: Path | None = None,
    rng: np.random.Generator | None = None,
) -> tuple[bytes, str]:
    """Return ``(float32_bytes, source)`` for one batch."""
    if imagenet_dir is not None:
        images = _list_images(imagenet_dir)
        if not images:
            raise FileNotFoundError(f"no images found under {imagenet_dir}")
        planes = []
        for index in range(batch_size):
            image = _load_image(images[index % len(images)])
            planes.append(preprocess_image(image))
        tensor = np.stack(planes, axis=0).astype(np.float32, copy=False)
        return np.ascontiguousarray(tensor).tobytes(), "imagenet"
    generator = rng if rng is not None else np.random.default_rng(SYNTHETIC_SEED)
    tensor = _synthetic_batch(batch_size, generator)
    return np.ascontiguousarray(tensor).tobytes(), "synthetic"


def generate_benign(
    corpus_root: Path,
    *,
    imagenet_dir: Path | None = None,
    batch_sizes: tuple[int, ...] = BATCH_SIZES,
) -> list[Artifact]:
    """Write benign dual artifacts for each requested batch size."""
    out_dir = corpus_root / "benign"
    rng = np.random.default_rng(SYNTHETIC_SEED)
    artifacts: list[Artifact] = []
    for batch_size in batch_sizes:
        tensor, source = build_batch(batch_size, imagenet_dir=imagenet_dir, rng=rng)
        expected = tensor_nbytes(batch_size)
        if len(tensor) != expected:
            raise RuntimeError(
                f"batch {batch_size} tensor is {len(tensor)} bytes, expected {expected}"
            )
        request_id = f"benign_b{batch_size}"
        payload = encode_model_infer_request(
            MODEL_NAME,
            MODEL_VERSION,
            request_id,
            tensor,
            batch_size,
        )
        artifacts.append(
            write_dual(
                out_dir,
                f"benign_b{batch_size}",
                payload,
                category="benign",
                expected="allow",
                notes=(
                    f"resnet50 FP32 NCHW [{batch_size},3,224,224] "
                    f"source={source} tensor_bytes={expected}"
                ),
            )
        )
    return artifacts
