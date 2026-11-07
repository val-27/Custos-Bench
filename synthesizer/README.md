# Custos Payload Synthesizer

Deterministic generator for KServe v2 `ModelInferRequest` benign tensors and wire-level adversarial Protobuf payloads.

## Usage

```bash
python3 -m pip install -r synthesizer/requirements.txt
python3 synthesizer/generate_all.py

# Optional: build benign batches from real ImageNet validation images
python3 synthesizer/generate_all.py --imagenet-dir /data/imagenet/val

# Opt-in 64 MiB ceiling twin. Omitted from the default corpus.
python3 synthesizer/generate_all.py --include-ceiling-blob
```

## Generated Corpus Summary (`59` manifest rows, `52` dual `.pb` / `.grpc` files)

`expected` is the KServe decision. The oracle sweep scores the server against it. Sweep-only framing and RPC rows are not `.pb` files under `benign/` or `malicious/`.

### 1. Benign KServe v2 Inference Payloads (`corpus/benign/`)
Targets `model_name = "resnet50"`, `model_version = "1"`, `input_name = "input_tensor"`, `datatype = "FP32"`, shape `[B, 3, 224, 224]` (`NCHW`):
* `benign_b1` — Batch 1 (`150,528` elements, `602,170 B` raw `.pb`)
* `benign_b2` — Batch 2 (`301,056` elements, `1,204,282 B` raw `.pb`)
* `benign_b4` — Batch 4 (`602,112` elements, `2,408,507 B` raw `.pb`)
* `benign_b8` — Batch 8 (`1,204,224` elements, `4,816,955 B` raw `.pb`)
* `benign_b16` — Batch 16 (`2,408,448` elements, `9,633,852 B` raw `.pb`)
* `benign_bytes_tensor` — `BYTES` `[1, 2]` with little-endian length prefixes

Oracle allow twins, also under `corpus/benign/`. They do not replace `benign_b1` as the default batch:
* `benign_multichunk_aligned` — FP32 `[4]` and FP32 `[1]`, raw chunks 16 then 4
* `benign_contents_fp32_unpacked` — FP32 `[1,4]` as four wire-type-5 `fp32_contents`, no Field 7
* `benign_contents_fp32_packed` — FP32 `[1,4]` as packed `fp32_contents` (float32 1, 2, 3, 4), no Field 7
* `benign_mixed_fp32_bytes` — FP32 `[1,4]` plus a correctly prefixed `BYTES` `[1,2]`
* `benign_param_binary_data_size` — `binary_data_size` on `InferParameter.int64_param` (field 2)
* `benign_shape_zero_axis` — FP32 `[1,0,224,224]` with an empty Field 7
* `benign_dtype_bool`, `benign_dtype_fp16`, `benign_dtype_bf16`, `benign_dtype_fp64` — shape `[1,4]` with a raw chunk of 4, 8, 8, and 32 bytes

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
  * `cve_2024_0088_shm_params_infer` — `shared_memory_region` / `offset` / `byte_size` on `InferParameter` fields `string_param = 3` and `int64_param = 2`
  * `grpc_compressed_flag_01` — gzip body, gRPC compression flag `0x01` on the `.grpc` sibling
* **Oracle rejects (`expected: "reject"`):**
  * `chunk_swap_fp32`, `chunk_omitted_fp32`, `chunk_swap_reordered` — per-chunk size and order
  * `contents_fp32_unpacked_short`, `contents_fp32_unpacked_ceiling` — contents cardinality against the shape, no Field 7
  * `bytes_length_prefix_oversize`, `bytes_masks_short_fp32` — `BYTES` length prefix, and a short FP32 chunk compensated by a fatter `BYTES` chunk
  * `shape_sum_four_ceilings` — four FP32 `[16777216]` tensors and no Field 7
  * `shape_packed_ones` — 100,000 packed dimensions of `1`. The sweep records `latency_ns` against the 250 ms ext_proc deadline
  * `datatype_fp64_short_raw`, `datatype_unknown_width` — FP64 with an FP32-sized chunk, and datatype `FP32 ` (trailing space)

### 3. Sweep-only rows
* `corpus/framing/frame_single.body` — one uncompressed frame, `ModelInfer`, `expected: allow`, `framing: http-body`
* `corpus/framing/frame_two_concat.body` — two frames in one HTTP body, `expected: reject`
* `corpus/framing/frame_stream_infer_two.body` — the same two-frame body on `ModelStreamInfer`, `expected: reject`
* `corpus/rpc/empty_model_infer.pb` — empty protobuf shared by `rpc_model_infer_empty` (`allow`) and `rpc_system_shared_memory_register`, `rpc_cuda_shared_memory_register`, `rpc_repository_model_load`, `rpc_repository_model_unload` (`reject`)

`benign_fp32_ceiling` (64 MiB raw chunk at the 16,777,216-element FP32 ceiling) is produced only with `--include-ceiling-blob`.
