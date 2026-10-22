//! Command-line surface for the three benchmark regimes.

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
}
