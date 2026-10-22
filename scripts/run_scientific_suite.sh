#!/usr/bin/env bash
# Parameterized scientific suite for Custos admission benchmarks.
#
#   --mode loopback
#       Single host. Pins Triton, Envoy, custos-proc, and custos-bench
#       to disjoint CPU sets via taskset when those binaries are launched
#       by this script. If the services are already running, only the
#       bench process is pinned and the suite drives --target.
#
#   --mode lan --target-host <IP>
#       Two-host LAN. This host is the client. Traffic is sent to the SUT
#       across a physical switch. Service pinning is the SUT operator's
#       responsibility (run setup_testbed.sh there).
#
# Executes N trials (default 5) across:
#   Topology A  unprotected Triton
#   Topology B  standard Envoy baseline
#   Topology C  Envoy + Custos
#
# Service start commands are optional. When omitted the suite assumes the
# topology is already listening on the corresponding port.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="loopback"
TARGET_HOST="127.0.0.1"
TRIALS=5
RPS_LIST="200 500 1000 2000"
DURATION=30
REQUESTS=100000
CONCURRENCY=2000
BATCH="benign_b1"
CORPUS="${ROOT}/corpus"
OUT="${ROOT}/results"
IFACE=""
PORT_A=8001
PORT_B=8002
PORT_C=8003
CORES_TRITON="0-3"
CORES_ENVOY="4-5"
CORES_CUSTOS="6-7"
CORES_BENCH="8-15"
TRITON_CMD=""
ENVOY_CMD=""
CUSTOS_CMD=""
SKIP_BURST=0

usage() {
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'
Options:
  --mode loopback|lan
  --target-host IP          SUT address (required for lan)
  --trials N                default 5
  --rps "200 500 1000 2000"
  --duration SEC            default 30
  --requests N              default 100000
  --concurrency N           saturating-burst fan-out (default 2000)
  --batch STEM              benign payload stem (default benign_b1)
  --corpus DIR
  --out DIR
  --iface IFACE             sysfs interface for wire throughput
  --port-a/--port-b/--port-c
  --cores-triton/--cores-envoy/--cores-custos/--cores-bench
  --triton-cmd/--envoy-cmd/--custos-cmd   optional launch commands
  --skip-burst
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --target-host) TARGET_HOST="$2"; shift 2 ;;
    --trials) TRIALS="$2"; shift 2 ;;
    --rps) RPS_LIST="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --requests) REQUESTS="$2"; shift 2 ;;
    --concurrency) CONCURRENCY="$2"; shift 2 ;;
    --batch) BATCH="$2"; shift 2 ;;
    --corpus) CORPUS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    --port-a) PORT_A="$2"; shift 2 ;;
    --port-b) PORT_B="$2"; shift 2 ;;
    --port-c) PORT_C="$2"; shift 2 ;;
    --cores-triton) CORES_TRITON="$2"; shift 2 ;;
    --cores-envoy) CORES_ENVOY="$2"; shift 2 ;;
    --cores-custos) CORES_CUSTOS="$2"; shift 2 ;;
    --cores-bench) CORES_BENCH="$2"; shift 2 ;;
    --triton-cmd) TRITON_CMD="$2"; shift 2 ;;
    --envoy-cmd) ENVOY_CMD="$2"; shift 2 ;;
    --custos-cmd) CUSTOS_CMD="$2"; shift 2 ;;
    --skip-burst) SKIP_BURST=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "${MODE}" != "loopback" && "${MODE}" != "lan" ]]; then
  echo "--mode must be loopback or lan" >&2
  exit 2
fi
if [[ "${MODE}" == "lan" && "${TARGET_HOST}" == "127.0.0.1" ]]; then
  echo "--mode lan requires --target-host <IP>" >&2
  exit 2
fi

BENCH="${ROOT}/custos-bench/target/release/custos-bench"
if [[ ! -x "${BENCH}" ]]; then
  echo "building custos-bench (release)"
  (cd "${ROOT}/custos-bench" && cargo build --release)
fi

mkdir -p "${OUT}/${MODE}"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
}
trap cleanup EXIT

pin_launch() {
  local cores="$1"
  local cmd="$2"
  if [[ -z "${cmd}" ]]; then
    return 0
  fi
  if [[ "${MODE}" == "loopback" ]] && command -v taskset >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    taskset -c "${cores}" bash -c "${cmd}" &
  else
    bash -c "${cmd}" &
  fi
  PIDS+=("$!")
}

if [[ "${MODE}" == "loopback" ]]; then
  pin_launch "${CORES_TRITON}" "${TRITON_CMD}"
  pin_launch "${CORES_ENVOY}" "${ENVOY_CMD}"
  pin_launch "${CORES_CUSTOS}" "${CUSTOS_CMD}"
fi

run_bench() {
  local topology="$1"
  local regime="$2"
  local rps="$3"
  local trial="$4"
  local port="$5"
  local label="${MODE}_${topology}_${regime}_rps${rps}_t${trial}"
  local -a cmd=(
    "${BENCH}"
    --regime "${regime}"
    --target "http://${TARGET_HOST}:${port}"
    --corpus "${CORPUS}"
    --batch "${BATCH}"
    --rps "${rps}"
    --requests "${REQUESTS}"
    --duration "${DURATION}"
    --concurrency "${CONCURRENCY}"
    --output-dir "${OUT}/${MODE}"
    --label "${label}"
  )
  if [[ -n "${IFACE}" ]]; then
    cmd+=(--net-iface "${IFACE}")
  fi
  echo "=== ${label} -> ${TARGET_HOST}:${port}"
  if [[ "${MODE}" == "loopback" ]] && command -v taskset >/dev/null 2>&1; then
    taskset -c "${CORES_BENCH}" "${cmd[@]}"
  else
    "${cmd[@]}"
  fi
}

topologies=(
  "A:${PORT_A}"
  "B:${PORT_B}"
  "C:${PORT_C}"
)

for spec in "${topologies[@]}"; do
  topology="${spec%%:*}"
  port="${spec##*:}"
  for ((trial = 1; trial <= TRIALS; trial++)); do
    for rps in ${RPS_LIST}; do
      run_bench "${topology}" "steady-benign" "${rps}" "${trial}" "${port}"
    done
    run_bench "${topology}" "interleaved" 1000 "${trial}" "${port}"
    if [[ "${SKIP_BURST}" -eq 0 ]]; then
      run_bench "${topology}" "saturating-burst" 0 "${trial}" "${port}"
    fi
  done
done

echo "suite complete: ${OUT}/${MODE}"
