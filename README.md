# custos-benchmarks

Scientific evaluation harness for the Custos Layer 7 gRPC admission controller.

Two subsystems:

- `synthesizer/` builds a deterministic corpus of KServe v2 ResNet-50 `ModelInferRequest` payloads and three families of wire-level protobuf exploits (nesting bombs, tensor shape overflows, unterminated varints).
- `custos-bench/` is an open-loop HTTP/2 gRPC load generator. It ships prebuilt `.pb` bytes through a passthrough tonic codec, so malformed varints never hit a client-side unmarshaler, and it records coordinated-omission latency (`T_completed - T_scheduled`) in an HdrHistogram from 1 ns to 60 s.

## Corpus

```bash
python3 -m pip install -r synthesizer/requirements.txt
python3 synthesizer/generate_all.py
# optional real images:
python3 synthesizer/generate_all.py --imagenet-dir /data/imagenet/val
```

Each payload is written twice under `corpus/{benign,malicious}/`:

| File | Contents | Consumer |
| --- | --- | --- |
| `*.pb` | Raw protobuf, no 5-byte gRPC header | `custos-bench` (tonic frames it) |
| `*.grpc` | `struct.pack(">BI", 0, len)` prepended | Offline unit tests |

`corpus/manifest.json` records category (`benign`, `nesting_bomb`, `shape_overflow`, `malformed_varint`), expected admission (`allow` / `reject`), and size. Nesting depths 15 and 16 are `allow`; depths ≥ 17 are `reject`.

## Load generator

```bash
cd custos-bench && cargo test && cargo clippy --all-targets -- -D warnings
cargo run --release -- \
  --regime steady-benign \
  --target http://127.0.0.1:8001 \
  --corpus ../corpus \
  --batch benign_b1 \
  --rps 1000 \
  --duration 30 \
  --net-iface lo \
  --watch-pids triton:1234,envoy:1235,custos:1236 \
  --output-dir ../results \
  --label loopback_A_steady_rps1000_t1
```

Regimes:

- `steady-benign` — open loop, 100% benign, constant `--rps`.
- `interleaved` — open loop, 99% benign / 1% malicious cycled in order, separate histograms.
- `saturating-burst` — `--concurrency` simultaneous attack RPCs (default use 2000).

Latency series exported for every trial: `P0 P50 P90 P95 P99 P99.9 P99.99 Max`, plus service time (`T_completed - T_actual_send`) so coordinated-omission inflation is visible. JSON and CSV land in `--output-dir`.

## Testbed

```bash
sudo scripts/setup_testbed.sh
scripts/run_scientific_suite.sh --mode loopback --iface lo --trials 5
scripts/run_scientific_suite.sh --mode lan --target-host 10.0.0.8 --iface enp3s0
python3 scripts/plot_results.py --results results/loopback --out figures/
```

`run_scientific_suite.sh` runs N=5 trials of topologies A (unprotected Triton, port 8001), B (Envoy, port 8002), and C (Envoy + Custos, port 8003). Loopback mode pins `custos-bench` with `taskset -c` and, when `--triton-cmd` / `--envoy-cmd` / `--custos-cmd` are set, pins those processes too.

## Layout

```text
synthesizer/     payload generators
custos-bench/    Rust load + telemetry harness
scripts/         testbed isolation, suite runner, plots
corpus/          generated .pb / .grpc / manifest.json
```
