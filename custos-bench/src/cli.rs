//! Command-line surface for the benchmark regimes.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

pub const MODEL_INFER_PATH: &str = "/inference.GRPCInferenceService/ModelInfer";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Regime {
    /// Open-loop constant arrival rate of 100% benign payloads.
    #[value(name = "steady-benign")]
    SteadyBenign,
    /// Open-loop mix: 99% benign, 1% malicious, cycled deterministically.
    Interleaved,
    /// Closed fan-out of simultaneous attack requests.
    #[value(name = "saturating-burst")]
    SaturatingBurst,
    /// Send each manifest entry once and score it against its expected decision.
    #[value(name = "oracle-sweep")]
    OracleSweep,
    /// Pre-registered paired-probe efficacy study (one attack + one twin per eligible pair).
    #[value(name = "paired-probe")]
    PairedProbe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProbeCell {
    /// Idle server: probes only, no background load.
    #[value(name = "l0")]
    L0,
    /// Open-loop benign background load at `--rps` during probe schedule.
    #[value(name = "l1")]
    L1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BackendKind {
    /// Official NVIDIA C++ `tritonserver`. Required for `--regime paired-probe`.
    #[value(name = "triton")]
    Triton,
    /// Deterministic simulated responder (`triton_sim`). Refused by `--regime paired-probe`.
    #[value(name = "sim")]
    Sim,
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "custos-bench",
    version,
    about = "Coordinated-omission-free open-loop gRPC load generator for Custos"
)]
pub struct Cli {
    /// Execution regime.
    #[arg(long, value_enum, default_value = "steady-benign")]
    pub regime: Regime,

    /// SUT authority, e.g. `http://127.0.0.1:8001`.
    #[arg(long, default_value = "http://127.0.0.1:8001")]
    pub target: String,

    /// Fully-qualified gRPC method path.
    #[arg(long, default_value = MODEL_INFER_PATH)]
    pub method: String,

    /// Directory containing `benign/*.pb` and `malicious/*.pb`.
    #[arg(long, default_value = "corpus")]
    pub corpus: PathBuf,

    /// Benign payload stem (without extension), e.g. `benign_b1`.
    #[arg(long, default_value = "benign_b1")]
    pub batch: String,

    /// Target offered rate for open-loop regimes.
    #[arg(long, default_value_t = 1000)]
    pub rps: u64,

    /// Number of requests to issue. Open-loop regimes also stop at `--duration`.
    #[arg(long, default_value_t = 10000)]
    pub requests: u64,

    /// Wall-clock bound for open-loop regimes, in seconds. `0` disables it.
    #[arg(long, default_value_t = 30)]
    pub duration: u64,

    /// In-flight cap. Saturating-burst fires this many simultaneous attacks.
    #[arg(long, default_value_t = 64)]
    pub concurrency: usize,

    /// Tokio worker threads. `0` selects the runtime default.
    #[arg(long, default_value_t = 0)]
    pub workers: usize,

    /// Per-RPC timeout in milliseconds.
    #[arg(long, default_value_t = 10000)]
    pub timeout_ms: u64,

    /// Maximum encoded message size accepted by the client, in bytes.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    pub max_message_bytes: usize,

    /// Interface whose `/sys/class/net/<iface>/statistics` counters are sampled.
    #[arg(long)]
    pub net_iface: Option<String>,

    /// Comma-separated PIDs (`triton,envoy,custos`) or `name:pid` pairs to sample.
    #[arg(long, value_delimiter = ',')]
    pub watch_pids: Vec<String>,

    /// Process names resolved via `/proc` when PIDs are not known (Linux).
    #[arg(long, value_delimiter = ',')]
    pub watch_names: Vec<String>,

    /// How often process RSS/CPU is sampled, in milliseconds.
    #[arg(long, default_value_t = 100)]
    pub sample_ms: u64,

    /// Directory for the JSON and CSV trial exports.
    #[arg(long, default_value = "results")]
    pub output_dir: PathBuf,

    /// Trial label embedded in the export filename.
    #[arg(long, default_value = "trial")]
    pub label: String,

    /// Malicious request ratio for `--regime interleaved`, in percent.
    #[arg(long, default_value_t = 1)]
    pub malicious_percent: u64,

    /// Use TLS (`https`) origin handling. Plain HTTP/2 prior knowledge is the default.
    #[arg(long, default_value_t = false)]
    pub tls: bool,

    /// Skip the RPC and only validate corpus loading plus histogram export.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,

    /// Load cell for `--regime paired-probe` (`l0` probe-only or `l1` with open-loop benign background).
    #[arg(long, value_enum, default_value = "l0")]
    pub cell: ProbeCell,

    /// Deterministic PRNG seed for Fisher-Yates pair shuffling in `--regime paired-probe`.
    #[arg(long, default_value_t = 0xC057_05F0_2026_1117)]
    pub trial_seed: u64,

    /// 1-based trial index embedded in probe `x-request-id` values (`t{trial}-{cell}-{pair}-{role}-{topo}-{seq}`).
    #[arg(long, default_value_t = 1)]
    pub trial_index: u32,

    /// Backend runtime under test (`triton` or `sim`). `paired-probe` refuses `sim` with exit code 2.
    #[arg(long, value_enum, default_value = "sim")]
    pub backend: BackendKind,

    /// Study identifier for `--regime paired-probe` output grouping (`results/<study-id>/`).
    #[arg(long, default_value = "cloud-loopback")]
    pub study_id: String,

    /// Topology tag (`A`, `B`, or `C`) embedded in probe `x-request-id` values.
    #[arg(long, default_value = "C")]
    pub topology_tag: String,

    /// Warmup duration in seconds before starting probes in `--cell l1`.
    #[arg(long, default_value_t = 5)]
    pub probe_warmup_secs: u64,

    /// Interval in milliseconds between consecutive probes in `--regime paired-probe`.
    #[arg(long, default_value_t = 200)]
    pub probe_interval_ms: u64,
}

impl Cli {
    pub fn duration_ns(&self) -> Option<u64> {
        if self.duration == 0 {
            None
        } else {
            Some(self.duration.saturating_mul(1_000_000_000))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_three_regimes() {
        let cli = Cli::parse_from([
            "custos-bench",
            "--regime",
            "interleaved",
            "--rps",
            "1000",
            "--watch-pids",
            "11,22,33",
        ]);
        assert_eq!(cli.regime, Regime::Interleaved);
        assert_eq!(cli.rps, 1000);
        assert_eq!(cli.watch_pids, ["11", "22", "33"]);
    }

    #[test]
    fn parses_oracle_sweep() {
        let cli = Cli::parse_from(["custos-bench", "--regime", "oracle-sweep"]);
        assert_eq!(cli.regime, Regime::OracleSweep);
    }

    #[test]
    fn parses_paired_probe_flags() {
        let cli = Cli::parse_from([
            "custos-bench",
            "--regime",
            "paired-probe",
            "--cell",
            "l1",
            "--trial-seed",
            "42",
            "--trial-index",
            "3",
            "--backend",
            "triton",
            "--study-id",
            "cloud-loopback-01",
            "--topology-tag",
            "C",
        ]);
        assert_eq!(cli.regime, Regime::PairedProbe);
        assert_eq!(cli.cell, ProbeCell::L1);
        assert_eq!(cli.trial_seed, 42);
        assert_eq!(cli.trial_index, 3);
        assert_eq!(cli.backend, BackendKind::Triton);
        assert_eq!(cli.study_id, "cloud-loopback-01");
        assert_eq!(cli.topology_tag, "C");
    }
}
