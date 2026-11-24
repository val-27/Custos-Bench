# Cloud GPU Loopback Runbook (`paired-probe` Efficacy Study)

This runbook executes the pre-registered paired-probe efficacy study on a single rented NVIDIA GPU VM (`L4`, `A10G`, `T4`, or `RTX 4090`) over loopback, copies `results/cloud-loopback/` off the host, and terminates the containers in the same session (< 45 minutes total rental time).

---

## 1. Host Prerequisites

* Dedicated Linux x86_64 VM with 1 NVIDIA GPU (driver $\ge 535$ + `nvidia-container-toolkit`), Docker, Envoy $\ge 1.28$, and Rust $\ge 1.85$.
* Ports bound on loopback (`127.0.0.1`):
  * **`:9001`** — Official NVIDIA Triton Inference Server (`nvcr.io/nvidia/tritonserver:24.08-py3`), serving both as **Topology A (Direct Triton)** and as the upstream backend for Envoy B and Envoy C.
  * **`:8002`** — **Topology B (Proxy Baseline)** (`deployments/bare-metal/envoy-baseline.yaml`, admin `:9902`).
  * **`:8003`** — **Topology C (Custos Production)** (`deployments/bare-metal/envoy-custos.yaml`, admin `:9903`, connected to `custos-proc` over `/var/run/custos/ext_proc.sock`).

---

## 2. Step-by-Step Execution

### Step 1: Isolate Testbed & Build Release Binaries
```bash
# Optional CPU governor lock (if permitted by guest hypervisor)
sudo ./Custos-Bench/scripts/setup_testbed.sh || true

# Build custos-proc and custos-bench in release mode
cargo build --release --manifest-path Custos-Gateway/Cargo.toml -p custos-proc
cargo build --release --manifest-path Custos-Bench/custos-bench/Cargo.toml

# Verify corpus and pre-registered pair lint
python3 Custos-Bench/synthesizer/generate_all.py
python3 Custos-Bench/synthesizer/lint_pairs.py
```

### Step 2: Start Official NVIDIA Triton Container on `:9001`
Ensure your `/models/resnet50` repository is mounted and ready:
```bash
STUDY_DIR="$(pwd)/Custos-Bench/results/cloud-loopback"
mkdir -p "${STUDY_DIR}"/{client,envoy,custos,score} /var/run/custos

docker run -d --rm --gpus=1 --name custos-triton \
  -p 127.0.0.1:8000:8000 \
  -p 127.0.0.1:9001:8001 \
  -v /models:/models:ro \
  nvcr.io/nvidia/tritonserver:24.08-py3 \
  tritonserver --model-repository=/models --log-verbose=1

# Wait until Triton reports READY
until curl -sf http://127.0.0.1:8000/v2/health/ready; do sleep 1; done
until curl -sf http://127.0.0.1:8000/v2/models/resnet50/ready; do sleep 1; done
```

### Step 3: Start `custos-proc` (with `CUSTOS_LOG_ADMITTED=true`) and Both Envoy Proxies
**Important:** `CUSTOS_LOG_ADMITTED=true` and `--log-format json` are required for `paired-probe` so the scorer can verify `decision = ALLOW` on every benign twin as well as `decision = DENY` on every blocked attack.
```bash
# 1. Start custos-proc sidecar daemon logging JSON to results/cloud-loopback/custos/
./Custos-Gateway/target/release/custos-proc \
  --socket-path /var/run/custos/ext_proc.sock \
  --log-format json \
  --log-admitted true \
  > "${STUDY_DIR}/custos/custos-proc.jsonl" 2>&1 &
CUSTOS_PID=$!

# 2. Start Topology B (Envoy Baseline on :8002)
envoy -c Custos-Gateway/deployments/bare-metal/envoy-baseline.yaml --base-id 2 \
  > "${STUDY_DIR}/envoy/envoy-b.jsonl" 2>&1 &
ENVOY_B_PID=$!

# 3. Start Topology C (Envoy + Custos on :8003)
envoy -c Custos-Gateway/deployments/bare-metal/envoy-custos.yaml --base-id 3 \
  > "${STUDY_DIR}/envoy/envoy-c.jsonl" 2>&1 &
ENVOY_C_PID=$!
sleep 2
```

### Step 4: Run the Pre-Registered `paired-probe` Study ($N = 5$ Trials across `L0`, `L1@100`, `L1@150`)
```bash
./Custos-Bench/scripts/run_scientific_suite.sh \
  --mode loopback \
  --port-a 9001 \
  --port-b 8002 \
  --port-c 8003 \
  --trials 5 \
  --efficacy-only \
  --backend triton \
  --study-id cloud-loopback

# Wait 2 seconds for Envoy stdout access log buffers to flush
sleep 2
```

### Step 5: Score the Study & Verify `efficacy_pairs.csv`
```bash
python3 Custos-Bench/scripts/score_efficacy.py \
  --study-dir "${STUDY_DIR}" \
  --corpus-dir Custos-Bench/corpus \
  --trials 5
```

### Step 6: Copy Results Off the VM & Tear Down Immediately
```bash
# Stop background daemons and Triton container
kill "${ENVOY_C_PID}" "${ENVOY_B_PID}" "${CUSTOS_PID}" || true
docker stop custos-triton || true

# Archive results for download to your workstation
tar -czf cloud-loopback-results.tar.gz -C Custos-Bench/results cloud-loopback
```
Once `cloud-loopback-results.tar.gz` is copied to your workstation via `scp`, terminate the rented cloud GPU instance immediately.
