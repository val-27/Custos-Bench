# Pre-Registered Paired-Probe Efficacy Protocol

**Status:** Pre-Registered Protocol (`Custos-Bench` & `Custos-Gateway`)  
**Study Host Label:** `cloud-loopback` (Official NVIDIA C++ `tritonserver`, isolated from `results/lan`)

---

## 1. Research Question & Unit of Analysis

* **Question:** While benign KServe v2 traffic is offered at a stated arrival rate (`L0` idle, `L1` at `100 RPS` and `150 RPS`), for which single-mutation `(attack, twin)` corpus pairs does `Custos` stop a request body that NVIDIA Triton Inference Server would otherwise accept or be harmed by, without rejecting its 1-mutation benign twin?
* **Unit of Analysis:** One eligible `(attack, twin)` pair at one load cell (`l0`, `l1_rps100`, `l1_rps150`) across all $N = 5$ trials.

---

## 2. Factors & Experimental Matrix

| Factor | Levels |
| :--- | :--- |
| **Topology** | **A** Direct Triton (`:8001` or `:9001`), **B** Envoy Proxy Baseline (`:8002`), **C** Envoy + `custos-proc` (`:8003`) |
| **Role** | `attack` (`expected: reject`), `twin` (`expected: allow`), `background` (`steady-benign` open-loop rotation) |
| **Load Cell** | `l0` (probes only, no background), `l1_rps100` (open-loop benign at 100 RPS), `l1_rps150` (open-loop benign at 150 RPS) |
| **Trial** | $N = 5$ trials per cell, rotating topology execution order (`ABC`, `BCA`, `CAB`) and Fisher-Yates pair order by `(trial_seed, trial_index)` |

---

## 3. Hypotheses & Decision Rule (Evaluated per Eligible Pair per Cell)

* **H1 (Custos Deny & Zero Upstream Bytes on C):** On Topology C, the attack client status is in `{"INVALID_ARGUMENT", "HTTP_400", "PERMISSION_DENIED"}`, the Envoy access log for that `x-request-id` has empty/`"-"` `upstream_host` and `upstream_wire_bytes_sent == 0`, and the `custos-proc` log for that `x-request-id` has `decision == "DENY"`.
* **H2 (Triton Harm or Acceptance on A):** On Topology A, the attack does **not** return that same clean admission reject from a live `tritonserver` (eligible A outcomes: `OK`, `INTERNAL`, `UNAVAILABLE`, `TRANSPORT`, `DEADLINE_EXCEEDED`, or `OTHER`).
* **H3 (Benign Twin Admission & Non-Zero Upstream Bytes):** The 1-mutation benign twin returns `OK` on A, B, and C, `upstream_wire_bytes_sent > 0` on B and C, and `custos-proc` logs `decision == "ALLOW"` on C.

### Deterministic Pair Label Table (`scripts/score_efficacy.py`)

| Final Label | Decision Rule (Must Hold Across All $N = 5$ Trials) |
| :--- | :--- |
| **`efficacious`** | `H1` and `H2` and `H3` hold in every trial. |
| **`parser_disagreement`** | `H1` and `H3` hold, and Topology A also returns an admission reject (`INVALID_ARGUMENT` / `HTTP_400`) while staying live. Excluded from the efficacy numerator. |
| **`false_positive`** | Twin is rejected on C (`status != "OK"`), `upstream_wire_bytes_sent == 0` on C, or `custos-proc` does not log `ALLOW`. |
| **`fail_open`** | Attack on C returns `OK`, or Envoy on C records `upstream_wire_bytes_sent > 0`. |
| **`proxy_effect`** | Envoy Baseline (Topology B) rejects the attack or sends `0` upstream bytes without `custos-proc`. |
| **`inconclusive`** | Missing Envoy or `custos-proc` log line for `request_id`, `TRANSPORT` on the twin, `ext_proc` timeout (`upstream_wire_bytes_sent == 0` with no `custos-proc` `DENY` line), or the $N = 5$ trials disagree. |

---

## 4. Pre-Registered Eligible Pairs (`14` Single-Mutation Pairs)

Validated prior to any trial by `python3 synthesizer/lint_pairs.py`:

| `pair_id` | Family | Attack Payload (`expected: reject`) | 1-Wire Twin (`expected: allow`) | Single Mutation |
| :--- | :--- | :--- | :--- | :--- |
| `nesting_bound_17` | `nesting_bound` | `nesting_depth_17` | `nesting_depth_16` | `depth_17_vs_16` |
| `shape_sign_neg` | `shape_sign` | `shape_neg_packed` | `benign_shape_pos_packed` | `sign_bit` |
| `shape_buffer_underread` | `shape_parity` | `shape_buffer_mismatch_underread` | `benign_b4` | `truncated_raw_chunk` |
| `shm_params_infer` | `parameters` | `cve_2024_0088_shm_params_infer` | `benign_param_binary_data_size` | `shared_memory_param_key` |
| `multichunk_swap` | `multichunk_fp32` | `chunk_swap_fp32` | `benign_multichunk_aligned` | `raw_chunk_order` |
| `multichunk_omitted` | `multichunk_fp32` | `chunk_omitted_fp32` | `benign_multichunk_aligned` | `raw_chunk_cardinality` |
| `multichunk_reordered` | `multichunk_fp32` | `chunk_swap_reordered` | `benign_multichunk_aligned` | `raw_chunk_wire_order_and_swap` |
| `contents_short` | `contents_fp32` | `contents_fp32_unpacked_short` | `benign_contents_fp32_unpacked` | `contents_cardinality_short` |
| `contents_ceiling` | `contents_fp32` | `contents_fp32_unpacked_ceiling` | `benign_contents_fp32_unpacked` | `contents_cardinality_ceiling` |
| `bytes_oversize_prefix` | `bytes_tensor` | `bytes_length_prefix_oversize` | `benign_bytes_tensor` | `bytes_u32_length_prefix` |
| `bytes_masks_short` | `bytes_tensor` | `bytes_masks_short_fp32` | `benign_mixed_fp32_bytes` | `bytes_chunk_compensates_short_fp32` |
| `dtype_fp64_short` | `dtype_fp64` | `datatype_fp64_short_raw` | `benign_dtype_fp64` | `raw_width` |
| `dtype_unknown_space` | `dtype_unknown` | `datatype_unknown_width` | `benign_dtype_fp16` | `datatype_token` |
| `framing_two_concat` | `framing` | `frame_two_concat` | `frame_single` | `concatenated_second_grpc_frame` |
