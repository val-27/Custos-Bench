# Custos Payload Synthesizer

Deterministic generator for KServe v2 `ModelInferRequest` benign tensors and wire-level adversarial Protobuf payloads.

## Usage

```bash
python3 -m pip install -r synthesizer/requirements.txt
python3 synthesizer/generate_all.py

# Optional: build benign batches from real ImageNet validation images
python3 synthesizer/generate_all.py --imagenet-dir /data/imagenet/val
```

## Generated Corpus Summary (`27` Dual `.pb` / `.grpc` Artifacts)

### 1. Benign KServe v2 Inference Payloads (`corpus/benign/`)
Targets `model_name = "resnet50"`, `model_version = "1"`, `input_name = "input_tensor"`, `datatype = "FP32"`, shape `[B, 3, 224, 224]` (`NCHW`):
* `benign_b1` — Batch 1 (`150,528` elements, `602,170 B` raw `.pb`)
* `benign_b2` — Batch 2 (`301,056` elements, `1,204,282 B` raw `.pb`)
* `benign_b4` — Batch 4 (`602,112` elements, `2,408,507 B` raw `.pb`)
* `benign_b8` — Batch 8 (`1,204,224` elements, `4,816,955 B` raw `.pb`)
* `benign_b16` — Batch 16 (`2,408,448` elements, `9,633,852 B` raw `.pb`)

### 2. Wire-Level Adversarial & Boundary Payloads (`corpus/malicious/`)
* **Nesting Bombs (`Field 5` recursive `Wire Type 2` chains):**
  * `nesting_depth_15`, `nesting_depth_16` — Boundary-acceptance validation (`expected: "allow"`, `D <= 16`)
  * `nesting_depth_17`, `nesting_depth_20`, `nesting_depth_50`, `nesting_depth_100`, `nesting_depth_250`, `nesting_depth_500` — Stack-exhaustion attacks (`expected: "reject"`, `D > 16`)
* **Tensor Shape Overflows & Buffer Parity Mismatch (`InferInputTensor.shape` packed `0x1A` & unpacked `0x18`):**
  * `shape_neg_packed`, `shape_neg_unpacked` — Negative dimension `[1, 3, -1, 224]` encoded as 10-byte two's-complement varint
  * `shape_wrap_64bit_packed`, `shape_wrap_64bit_unpacked` — Multiplicative 64-bit integer overflow `[2, 2^62, 2]` (`product ≡ 0 mod 2^64`)
  * `shape_oom_massive_packed`, `shape_oom_massive_unpacked` — Buffer ceiling breach `[1024, 1024, 1024]` (`1.07B` elements > `16.77M` ceiling)
  * `shape_reordered_tail` — `16 KiB` `raw_input_contents` (Field 7) placed *before* malicious `inputs` (Field 5) to defeat prefix-only scanners
  * `shape_buffer_mismatch_underread` — `CVE-2025-23320` shape `[4, 3, 224, 224]` `FP32` (`2,408,448 B` expected) with `64 B` in `raw_input_contents`
* **Malformed Varints (`Wire Type 0` continuation & overflow exploits):**
  * `varint_unterminated_11` — Tag `0x08` + `11` consecutive `0xFF` bytes (`MSB = 1`)
  * `varint_unterminated_64` — Tag `0x08` + `64` consecutive `0x80` bytes (`MSB = 1`)
  * `varint_10th_byte_overflow` — Tag `0x08` + `9x 0xFF` + `0x7F` (overflows 64-bit integer on 10th byte)
  * `varint_truncated_eof` — Tag `0x08` + `3x 0xFF` followed by premature EOF
* **CVE Wire-Type & AST Amplification Exploits:**
  * `sgroup_wire_type_3_bomb` — `CVE-2024-7254` (`64` nested Protobuf Wire Type 3 `SGROUP` tags bypassing recursion depth counters)
  * `unknown_field_ast_flood` — `CVE-2021-22569` / `CVE-2022-1941` (`1,500` shallow 2-byte unknown tags at `D = 0`, exceeding the `1,024` tag ceiling)
