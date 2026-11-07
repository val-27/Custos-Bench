# Custos-Bench

**Scientific Evaluation & Open-Loop Load Generation Suite for Custos Layer 7 gRPC Admission Control**

---

## 1. Overview & Scientific Rationale

Standard gRPC benchmarking tools (such as `ghz` or `wrk2`) fail when evaluating wire-level Protobuf admission controllers for two reasons:
1. **Client-Side Serialization Refusal:** Standard Protobuf stubs validate and canonicalize messages before transmission, making it impossible to emit unterminated 11-byte varints, 10th-byte 64-bit overflows, or 500-deep recursive submessages onto the wire.
2. **Coordinated Omission:** Closed-loop load generators wait for an in-flight RPC to return before issuing the next request. When a malicious payload stalls or crashes an unprotected inference server, closed-loop clients throttle their own send rate and drastically under-report tail latency (`P99`–`P99.99`).

**`Custos-Bench`** solves both challenges through two tightly coupled subsystems:
* **`synthesizer/` (Deterministic Wire Corpus Generator):** Synthesizes valid KServe v2 `ModelInferRequest` tensors (`ResNet-50 v1.5`, `FP32`, `NCHW`) across batch sizes `1, 2, 4, 8, 16` (`602 KB` to `9.63 MB`) alongside three families of raw binary Protobuf exploits (**Nesting Bombs**, **Tensor Shape Overflows**, and **Malformed Varints**).
* **`custos-bench/` (Coordinated-Omission-Free Open-Loop Harness):** Ships pre-built `.pb` wire payloads directly through a passthrough Tonic [`RawCodec`](./custos-bench/src/raw_codec.rs) (bypassing client-side Protobuf marshaling) and schedules requests on an open-loop nanosecond clock (`L_k = T_completed - T_scheduled`), recording both **Coordinated-Omission Latency** and raw **Service Time** (`S_k = T_completed - T_actual_send`) in an `HdrHistogram` (`1 ns` to `60 s`, 3 significant figures).

---

## 2. Evaluation Architectures

To isolate the latency, throughput, CPU/RSS cost, and survivability impact of [`Custos-Gateway`](../Custos-Gateway), benchmarks are executed across three unified architectures on identical hardware:

| Architecture | Data Path | Description |
| :--- | :--- | :--- |
| **Unprotected Control (Direct Triton)** | `custos-bench ──► NVIDIA Triton (:8001)` | Control group with zero L7 wire defense; establishes the raw model inference latency floor and demonstrates runtime crashes/stalls under attack. |
| **Proxy Baseline (Envoy Only)** | `custos-bench ──► Envoy (:8002) ──► Triton (:9001)` | Isolates the baseline latency and CPU/RSS overhead of industry-standard HTTP/2 L7 proxying without the `custos-proc` sidecar. |
| **Custos Production (Gateway + Sidecar)** | `custos-bench ──► Envoy (:8003) ══[UDS]══► custos-proc ──► Triton (:9001)` | The production Gateway + Native Sidecar architecture. Evaluates zero-copy TLV wire inspection efficacy (`100%` attack drop rate, `0%` false positives), microsecond latency delta over Proxy Baseline, and server survival. |

---

## 3. Target Metrics & Benchmark Regimes

### Three Workload Regimes
* **`steady-benign`:** Open-loop `100%` benign KServe v2 inference load (`100`, `150`, `200`, `500` RPS) across batch sizes `1..16` to quantify steady-state latency overhead.
* **`interleaved`:** Open-loop `99%` benign / `1%` malicious deterministic traffic mix to measure tail-latency degradation (`P99`, `P99.9`, `P99.99`), head-of-line blocking, False Positive Rate (`FPR`), and True Positive Drop Rate (`TP-drop`).
* **`saturating-burst`:** Simultaneous fan-out of concurrent RPCs (`90%` adversarial exploits + `10%` legitimate `benign_b1` inference requests) to evaluate legitimate user `P99` tail latency and survival under an active flood alongside total data-path Peak RSS (`Triton + Envoy + Sidecar`).

### Four Evaluation Pillars Exported per Trial (JSON & CSV)
1. **Filtering Accuracy (`accuracy`):** `true_positive_drop_rate` (`malicious_rejected / malicious_sent`, `N/A` on `steady-benign`) and `false_positive_rate` (`benign_rejected / benign_sent`).
2. **Latency Overhead (`latency` & `service_time`):** `P0, P50, P90, P95, P99, P99.9, P99.99, Max` in nanoseconds for overall, benign-only, and malicious-only traffic.
3. **Resource Efficiency (`processes` & `wire`):** `/proc/<pid>/stat` and `/proc/<pid>/status` sampling (`avg_cpu_percent`, `peak_cpu_percent`, `avg_rss_kb`, `peak_rss_kb`, plus normalized `cpu_per_1000_requests_percent` and `rss_per_1000_requests_kb`) alongside `/sys/class/net/<iface>/statistics` wire throughput.
4. **Server Survival (`status`):** Breakdown of `OK`, `INVALID_ARGUMENT`, `HTTP_400`, `UNAVAILABLE`, `INTERNAL`, `DEADLINE_EXCEEDED`, and `TRANSPORT` connection resets.

---

## 4. Generating the Payload Corpus

```bash
python3 -m pip install -r synthesizer/requirements.txt
python3 synthesizer/generate_all.py

# Optional: sample real ImageNet validation images instead of seeded synthetic tensors
python3 synthesizer/generate_all.py --imagenet-dir /data/imagenet/val
```

Each payload is emitted in two formats under `corpus/{benign,malicious}/`:

| Extension | Wire Format | Consumer |
| :--- | :--- | :--- |
| `*.pb` | Raw Protobuf message bytes (no 5-byte gRPC frame header) | `custos-bench` (`RawCodec` lets Tonic prepend the 5-byte gRPC header on the wire) |
| `*.grpc` | Pre-framed `struct.pack(">BI", flag, len) + pb_bytes` | Offline unit tests (`custos_core::inspect_payload`) |

`corpus/manifest.json` indexes all 30 generated payloads:
* **6 Benign Payloads (`corpus/benign/`):** `benign_b1` (`602 KB`), `benign_b2` (`1.20 MB`), `benign_b4` (`2.41 MB`), `benign_b8` (`4.82 MB`), `benign_b16` (`9.63 MB`), and `benign_bytes_tensor` (`134 B` variable-length `BYTES` string tensor `[1, 2]`).
* **2 Boundary-Acceptance Payloads (`corpus/malicious/nesting_depth_{15,16}`):** Verify `MAX_DEPTH = 16` boundary admission (`expected: "allow"`). Automatically excluded from active attack bursts by `Corpus::load` so `interleaved` and `saturating-burst` only fire true exploits.
* **22 Adversarial Exploit Payloads (`corpus/malicious/`):**
  * **Nesting Bombs (`6`):** `nesting_depth_{17,20,50,100,250,500}`
  * **Tensor Shape Overflows & Buffer Parity Mismatch (`8`):** `shape_neg_{packed,unpacked}`, `shape_wrap_64bit_{packed,unpacked}`, `shape_oom_massive_{packed,unpacked}`, `shape_reordered_tail` (`16 KiB` Field 7 preceding malicious Field 5), `shape_buffer_mismatch_underread` (`CVE-2025-23334`-class OOB read — `[4,3,224,224]` `FP32` declaring `2.41 MB` with `64 B` `raw_input_contents`)
  * **Malformed Varints (`4`):** `varint_unterminated_11`, `varint_unterminated_64`, `varint_10th_byte_overflow`, `varint_truncated_eof`
  * **CVE Wire, Parameter & Compression Exploits (`4`):** `sgroup_wire_type_3_bomb` (`CVE-2024-7254`-class — 64 nested Wire Type 3 `SGROUP` tags), `unknown_field_ast_flood` (`CVE-2022-1941` / `CVE-2021-22569`-class — 1,500 shallow unknown tags at `D=0`), `cve_2024_0088_shm_params_infer` (`CVE-2024-0088` — `shared_memory_region`/`offset`/`byte_size` injected inside `ModelInfer` `InferInputTensor.parameters`), and `grpc_compressed_flag_01` (`flag = 0x01` `gzip`-compressed gRPC frame concealing an OOM tensor payload)

---

## 5. Home Lab Setup & Execution Guide

### Step 1: Prepare the Triton `resnet50` Model Repository
`benign_generator.py` targets a KServe v2 model with:
* **Model Name:** `resnet50` (version `1`)
* **Input Tensor Name:** `input_tensor`
* **Datatype:** `FP32`
* **Dimensions:** `[-1, 3, 224, 224]` (`NCHW`)

Ensure your Triton model repository (`/models/resnet50/config.pbtxt`) defines `name: "input_tensor"` with `data_type: TYPE_FP32` and `dims: [ 3, 224, 224 ]` (with `max_batch_size: 16`).

### Step 2: Isolate the Linux Testbed
Lock CPU frequency scaling governors to `performance`, disable swap, and raise kernel socket backlogs:
```bash
sudo scripts/setup_testbed.sh
```

### Step 3: Build & Verify `custos-bench`
```bash
cd custos-bench
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
cd ..
```

### Step 4: Run Individual Trials or the Full Scientific Suite

**Single Trial Example:**
```bash
./custos-bench/target/release/custos-bench \
  --regime interleaved \
  --target http://127.0.0.1:8001 \
  --corpus ./corpus \
  --batch benign_b1 \
  --rps 1000 \
  --duration 30 \
  --net-iface lo \
  --watch-names tritonserver,envoy,custos-proc \
  --output-dir ./results/manual \
  --label topo_C_interleaved_rps1000_t1
```

**Automated Multi-Trial Suite (`N=5` trials across Topologies A, B, C):**
```bash
# Single-host loopback with taskset core pinning
scripts/run_scientific_suite.sh --mode loopback --iface lo --trials 5

# Two-host LAN benchmark (client driving remote SUT)
scripts/run_scientific_suite.sh --mode lan --target-host 10.0.0.8 --iface enp3s0 --trials 5
```

### Step 5: Generate Publication Figures
```bash
python3 scripts/plot_results.py --results results/loopback --out figures/
```
Generates `latency_cdf.png/.pdf` (`P50`–`P99.99` with 95% Student-$t$ confidence intervals), `throughput.png/.pdf`, and `utilization.png/.pdf` (Peak CPU % and Peak RSS MiB).
